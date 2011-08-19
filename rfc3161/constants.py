from pyasn1.type import univ

__all__ = ('id_kp_timeStamping','id_sha1', 'id_ct_TSTInfo',)

id_kp_timeStamping = univ.ObjectIdentifier((1,3,6,1,5,5,7,3,8))
id_sha1 = univ.ObjectIdentifier((1,3,14,3,2,26))
id_ct_TSTInfo = univ.ObjectIdentifier((1,2,840,113549,1,9,16,1,4))
