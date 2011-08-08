from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459
import rfc3161
import hashlib
import urllib2
import time

__all__ = ('timestamp',)

def timestamp(url, data=None, sha1=None):
    algorithm_identifier = rfc2459.AlgorithmIdentifier()
    algorithm_identifier.setComponentByPosition(0, rfc3161.id_sha1)
    message_imprint = rfc3161.MessageImprint()
    message_imprint.setComponentByPosition(0, algorithm_identifier)
    if data:
        sha1 = hashlib.sha1(data).digest()
    elif sha1:
        assert len(sha1) == 20
    else:
        raise ValueError('You must pass some data to digest, or the sha1 digest')
    message_imprint.setComponentByPosition(1, sha1)
    request = rfc3161.TimeStampReq()
    request.setComponentByPosition(0, 'v1')
    request.setComponentByPosition(1, message_imprint)
    request.setComponentByPosition(4)
    binary_request = encoder.encode(request)
    http_request = urllib2.Request(url, binary_request,
            { 'Content-Type': 'application/timestamp-query' })
    response = urllib2.urlopen(http_request).read()
    return decoder.decode(response, asn1Spec=rfc3161.TimeStampResp())
