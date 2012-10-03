from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error
import M2Crypto.X509 as X509
import socket

import rfc3161
import hashlib
import urllib2
import base64

__all__ = ('RemoteTimestamper','check_timestamp','get_hash_oid', 'TimestampingError')

id_attribute_messageDigest = univ.ObjectIdentifier((1,2,840,113549,1,9,4,))

def get_hash_oid(hashname):
    return rfc3161.__dict__['id_'+hashname]

class TimestampingError(RuntimeError):
    pass

def check_timestamp(tst, certificate, data=None, sha1=None, hashname=None):
    hashobj = hashlib.new(hashname or 'sha1')
    if not sha1:
        if not data:
            raise ValueError("check_timestamp requires data or sha1 argument")
        hashobj.update(data)
        digest = hashobj.digest()
    else:
        digest = sha1

    if not isinstance(tst, rfc3161.TimeStampToken):
        tst, substrate = decoder.decode(tst, asn1Spec=rfc3161.TimeStampToken())
        if substrate:
            return False, "extra data after tst"
    signed_data = tst.content
    if certificate != "":
        try:
            certificate = X509.load_cert_string(certificate, X509.FORMAT_PEM)
        except:
            certificate = X509.load_cert_string(certificate, X509.FORMAT_DER)
    else:
        return False, "missing certificate"
    # check message imprint with respect to locally computed digest
    message_imprint = tst.tst_info.message_imprint
    if message_imprint.hash_algorithm[0] != get_hash_oid(hashobj.name) or \
        str(message_imprint.hashed_message) != digest:
            return False, 'Message imprint mismatch'
    #
    if not len(signed_data['signerInfos']):
        return False, 'No signature'
    # We validate only one signature
    signer_info = signed_data['signerInfos'][0]
    # check content type
    if tst.content['contentInfo']['contentType'] != rfc3161.id_ct_TSTInfo:
        return False, "Signed content type is wrong: %s != %s" % (
            tst.content['contentInfo']['contentType'], rfc3161.id_ct_TSTInfo)

    # check signed data digest
    content = str(decoder.decode(str(tst.content['contentInfo']['content']),
        asn1Spec=univ.OctetString())[0])
    # if there is authenticated attributes, they must contain the message
    # digest and they are the signed data otherwise the content is the
    # signed data
    if len(signer_info['authenticatedAttributes']):
        authenticated_attributes = signer_info['authenticatedAttributes']
        content_digest = hashlib.sha1(content).digest()
        for authenticated_attribute in authenticated_attributes:
            if authenticated_attribute[0] == id_attribute_messageDigest:
                try:
                    signed_digest = str(decoder.decode(str(authenticated_attribute[1][0]),
                            asn1Spec=univ.OctetString())[0])
                    if signed_digest != content_digest:
                        return False, 'Content digest != signed digest'
                    s = univ.SetOf()
                    for i, x in enumerate(authenticated_attributes):
                        s.setComponentByPosition(i, x)
                    signed_data = encoder.encode(s)
                    break
                except PyAsn1Error:
                    raise
                    pass
        else:
            return False, 'No signed digest'
    else:
        signed_data = content
    # check signature
    signature = signer_info['encryptedDigest']
    pub_key = certificate.get_pubkey()
    pub_key.verify_init()
    pub_key.verify_update(signed_data)
    if pub_key.verify_final(str(signature)) != 1:
        return False, 'Bad signature'
    return True, ''



class RemoteTimestamper(object):
    def __init__(self, url, certificate=None, capath=None, cafile=None, username=None, password=None, hashname=None):
        self.url = url
        self.certificate = certificate
        self.capath = capath
        self.cafile = cafile
        self.username = username
        self.password = password
        self.hashobj = hashlib.new(hashname or 'sha1')

    def check_response(self, response, digest):
        '''
           Check validity of a TimeStampResponse
        '''
        tst = response.time_stamp_token
        return check_timestamp(tst, sha1=digest, certificate=self.certificate, hashname=self.hashobj.name)

    def __call__(self, data=None, sha1=None):
        algorithm_identifier = rfc2459.AlgorithmIdentifier()
        algorithm_identifier.setComponentByPosition(0, get_hash_oid(self.hashobj.name))
        message_imprint = rfc3161.MessageImprint()
        message_imprint.setComponentByPosition(0, algorithm_identifier)
        if data:
            self.hashobj.update(data)
            sha1 = self.hashobj.digest()
        elif sha1:
            assert len(sha1) == self.hashobj.digest_size
        else:
            raise ValueError('You must pass some data to digest, or the sha1 digest')
        message_imprint.setComponentByPosition(1, sha1)
        request = rfc3161.TimeStampReq()
        request.setComponentByPosition(0, 'v1')
        request.setComponentByPosition(1, message_imprint)
        request.setComponentByPosition(4)
        binary_request = encoder.encode(request)
        http_request = urllib2.Request(self.url, binary_request,
                { 'Content-Type': 'application/timestamp-query' })
        if self.username != None:
            base64string = base64.standard_b64encode('%s:%s' % (self.username, self.password))
            http_request.add_header("Authorization", "Basic %s" % base64string)
        try:
            response = urllib2.urlopen(http_request).read()
        except (IOError, socket.error), e:
            raise TimestampingError('Unable to send the request to %s' % self.url, e)
        # open('response.tsr', 'w').write(response)
        tst_response, substrate = decoder.decode(response, asn1Spec=rfc3161.TimeStampResp())
        if substrate:
            return False, 'Extra data returned'
        result, message = self.check_response(tst_response, sha1)
        if result:
            return encoder.encode(tst_response.time_stamp_token), ''
        else:
            return False, message


