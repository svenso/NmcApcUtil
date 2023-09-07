using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NmcApcUtil
{
    public class crypt
    {
        // Fields
        public const int ALGO_NONE = 0;
        public const int ALGO_DES = 1;
        public const int ALGO_3DES = 2;
        public const int ALGO_IDEA = 3;
        public const int ALGO_CAST = 4;
        public const int ALGO_RC2 = 5;
        public const int ALGO_RC4 = 6;
        public const int ALGO_RESERVED1 = 7;
        public const int ALGO_AES = 8;
        public const int ALGO_RESERVED2 = 9;
        public const int ALGO_DH = 100;
        public const int ALGO_RSA = 0x65;
        public const int ALGO_DSA = 0x66;
        public const int ALGO_ELGAMAL = 0x67;
        public const int ALGO_RESERVED3 = 0x68;
        public const int ALGO_ECDSA = 0x69;
        public const int ALGO_ECDH = 0x6a;
        public const int ALGO_RESERVED4 = 200;
        public const int ALGO_RESERVED5 = 0xc9;
        public const int ALGO_MD5 = 0xca;
        public const int ALGO_SHA1 = 0xcb;
        public const int ALGO_RESERVED6 = 0xcc;
        public const int ALGO_SHA2 = 0xcd;
        public const int ALGO_SHA256 = 0xcd;
        public const int ALGO_SHAng = 0xce;
        public const int ALGO_RESREVED_7 = 300;
        public const int ALGO_HMAC_SHA1 = 0x12d;
        public const int ALGO_RESERVED8 = 0x12e;
        public const int ALGO_HMAC_SHA2 = 0x12f;
        public const int ALGO_HMAC_SHAng = 0x130;
        public const int ALGO_LAST = 0x131;
        public const int ALGO_FIRST_CONVENTIONAL = 1;
        public const int ALGO_LAST_CONVENTIONAL = 0x63;
        public const int ALGO_FIRST_PKC = 100;
        public const int ALGO_LAST_PKC = 0xc7;
        public const int ALGO_FIRST_HASH = 200;
        public const int ALGO_LAST_HASH = 0x12b;
        public const int ALGO_FIRST_MAC = 300;
        public const int ALGO_LAST_MAC = 0x18f;
        public const int MODE_NONE = 0;
        public const int MODE_ECB = 1;
        public const int MODE_CBC = 2;
        public const int MODE_CFB = 3;
        public const int MODE_GCM = 4;
        public const int MODE_LAST = 5;
        public const int KEYSET_NONE = 0;
        public const int KEYSET_FILE = 1;
        public const int KEYSET_HTTP = 2;
        public const int KEYSET_LDAP = 3;
        public const int KEYSET_ODBC = 4;
        public const int KEYSET_DATABASE = 5;
        public const int KEYSET_ODBC_STORE = 6;
        public const int KEYSET_DATABASE_STORE = 7;
        public const int KEYSET_LAST = 8;
        public const int DEVICE_NONE = 0;
        public const int DEVICE_FORTEZZA = 1;
        public const int DEVICE_PKCS11 = 2;
        public const int DEVICE_CRYPTOAPI = 3;
        public const int DEVICE_HARDWARE = 4;
        public const int DEVICE_LAST = 5;
        public const int CERTTYPE_NONE = 0;
        public const int CERTTYPE_CERTIFICATE = 1;
        public const int CERTTYPE_ATTRIBUTE_CERT = 2;
        public const int CERTTYPE_CERTCHAIN = 3;
        public const int CERTTYPE_CERTREQUEST = 4;
        public const int CERTTYPE_REQUEST_CERT = 5;
        public const int CERTTYPE_REQUEST_REVOCATION = 6;
        public const int CERTTYPE_CRL = 7;
        public const int CERTTYPE_CMS_ATTRIBUTES = 8;
        public const int CERTTYPE_RTCS_REQUEST = 9;
        public const int CERTTYPE_RTCS_RESPONSE = 10;
        public const int CERTTYPE_OCSP_REQUEST = 11;
        public const int CERTTYPE_OCSP_RESPONSE = 12;
        public const int CERTTYPE_PKIUSER = 13;
        public const int CERTTYPE_LAST = 14;
        public const int FORMAT_NONE = 0;
        public const int FORMAT_AUTO = 1;
        public const int FORMAT_CRYPTLIB = 2;
        public const int FORMAT_CMS = 3;
        public const int FORMAT_PKCS7 = 3;
        public const int FORMAT_SMIME = 4;
        public const int FORMAT_PGP = 5;
        public const int FORMAT_LAST = 6;
        public const int SESSION_NONE = 0;
        public const int SESSION_SSH = 1;
        public const int SESSION_SSH_SERVER = 2;
        public const int SESSION_SSL = 3;
        public const int SESSION_TLS = 3;
        public const int SESSION_SSL_SERVER = 4;
        public const int SESSION_TLS_SERVER = 4;
        public const int SESSION_RTCS = 5;
        public const int SESSION_RTCS_SERVER = 6;
        public const int SESSION_OCSP = 7;
        public const int SESSION_OCSP_SERVER = 8;
        public const int SESSION_TSP = 9;
        public const int SESSION_TSP_SERVER = 10;
        public const int SESSION_CMP = 11;
        public const int SESSION_CMP_SERVER = 12;
        public const int SESSION_SCEP = 13;
        public const int SESSION_SCEP_SERVER = 14;
        public const int SESSION_CERTSTORE_SERVER = 15;
        public const int SESSION_LAST = 0x10;
        public const int USER_NONE = 0;
        public const int USER_NORMAL = 1;
        public const int USER_SO = 2;
        public const int USER_CA = 3;
        public const int USER_LAST = 4;
        public const int ATTRIBUTE_NONE = 0;
        public const int PROPERTY_FIRST = 1;
        public const int PROPERTY_HIGHSECURITY = 2;
        public const int PROPERTY_OWNER = 3;
        public const int PROPERTY_FORWARDCOUNT = 4;
        public const int PROPERTY_LOCKED = 5;
        public const int PROPERTY_USAGECOUNT = 6;
        public const int PROPERTY_NONEXPORTABLE = 7;
        public const int PROPERTY_LAST = 8;
        public const int GENERIC_FIRST = 9;
        public const int ATTRIBUTE_ERRORTYPE = 10;
        public const int ATTRIBUTE_ERRORLOCUS = 11;
        public const int ATTRIBUTE_ERRORMESSAGE = 12;
        public const int ATTRIBUTE_CURRENT_GROUP = 13;
        public const int ATTRIBUTE_CURRENT = 14;
        public const int ATTRIBUTE_CURRENT_INSTANCE = 15;
        public const int ATTRIBUTE_BUFFERSIZE = 0x10;
        public const int GENERIC_LAST = 0x11;
        public const int OPTION_FIRST = 100;
        public const int OPTION_INFO_DESCRIPTION = 0x65;
        public const int OPTION_INFO_COPYRIGHT = 0x66;
        public const int OPTION_INFO_MAJORVERSION = 0x67;
        public const int OPTION_INFO_MINORVERSION = 0x68;
        public const int OPTION_INFO_STEPPING = 0x69;
        public const int OPTION_ENCR_ALGO = 0x6a;
        public const int OPTION_ENCR_HASH = 0x6b;
        public const int OPTION_ENCR_MAC = 0x6c;
        public const int OPTION_PKC_ALGO = 0x6d;
        public const int OPTION_PKC_KEYSIZE = 110;
        public const int OPTION_SIG_ALGO = 0x6f;
        public const int OPTION_SIG_KEYSIZE = 0x70;
        public const int OPTION_KEYING_ALGO = 0x71;
        public const int OPTION_KEYING_ITERATIONS = 0x72;
        public const int OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES = 0x73;
        public const int OPTION_CERT_VALIDITY = 0x74;
        public const int OPTION_CERT_UPDATEINTERVAL = 0x75;
        public const int OPTION_CERT_COMPLIANCELEVEL = 0x76;
        public const int OPTION_CERT_REQUIREPOLICY = 0x77;
        public const int OPTION_CMS_DEFAULTATTRIBUTES = 120;
        public const int OPTION_SMIME_DEFAULTATTRIBUTES = 120;
        public const int OPTION_KEYS_LDAP_OBJECTCLASS = 0x79;
        public const int OPTION_KEYS_LDAP_OBJECTTYPE = 0x7a;
        public const int OPTION_KEYS_LDAP_FILTER = 0x7b;
        public const int OPTION_KEYS_LDAP_CACERTNAME = 0x7c;
        public const int OPTION_KEYS_LDAP_CERTNAME = 0x7d;
        public const int OPTION_KEYS_LDAP_CRLNAME = 0x7e;
        public const int OPTION_KEYS_LDAP_EMAILNAME = 0x7f;
        public const int OPTION_DEVICE_PKCS11_DVR01 = 0x80;
        public const int OPTION_DEVICE_PKCS11_DVR02 = 0x81;
        public const int OPTION_DEVICE_PKCS11_DVR03 = 130;
        public const int OPTION_DEVICE_PKCS11_DVR04 = 0x83;
        public const int OPTION_DEVICE_PKCS11_DVR05 = 0x84;
        public const int OPTION_DEVICE_PKCS11_HARDWAREONLY = 0x85;
        public const int OPTION_NET_SOCKS_SERVER = 0x86;
        public const int OPTION_NET_SOCKS_USERNAME = 0x87;
        public const int OPTION_NET_HTTP_PROXY = 0x88;
        public const int OPTION_NET_CONNECTTIMEOUT = 0x89;
        public const int OPTION_NET_READTIMEOUT = 0x8a;
        public const int OPTION_NET_WRITETIMEOUT = 0x8b;
        public const int OPTION_MISC_ASYNCINIT = 140;
        public const int OPTION_MISC_SIDECHANNELPROTECTION = 0x8d;
        public const int OPTION_CONFIGCHANGED = 0x8e;
        public const int OPTION_SELFTESTOK = 0x8f;
        public const int OPTION_LAST = 0x90;
        public const int CTXINFO_FIRST = 0x3e8;
        public const int CTXINFO_ALGO = 0x3e9;
        public const int CTXINFO_MODE = 0x3ea;
        public const int CTXINFO_NAME_ALGO = 0x3eb;
        public const int CTXINFO_NAME_MODE = 0x3ec;
        public const int CTXINFO_KEYSIZE = 0x3ed;
        public const int CTXINFO_BLOCKSIZE = 0x3ee;
        public const int CTXINFO_IVSIZE = 0x3ef;
        public const int CTXINFO_KEYING_ALGO = 0x3f0;
        public const int CTXINFO_KEYING_ITERATIONS = 0x3f1;
        public const int CTXINFO_KEYING_SALT = 0x3f2;
        public const int CTXINFO_KEYING_VALUE = 0x3f3;
        public const int CTXINFO_KEY = 0x3f4;
        public const int CTXINFO_KEY_COMPONENTS = 0x3f5;
        public const int CTXINFO_IV = 0x3f6;
        public const int CTXINFO_HASHVALUE = 0x3f7;
        public const int CTXINFO_LABEL = 0x3f8;
        public const int CTXINFO_PERSISTENT = 0x3f9;
        public const int CTXINFO_LAST = 0x3fa;
        public const int CERTINFO_FIRST = 0x7d0;
        public const int CERTINFO_SELFSIGNED = 0x7d1;
        public const int CERTINFO_IMMUTABLE = 0x7d2;
        public const int CERTINFO_XYZZY = 0x7d3;
        public const int CERTINFO_CERTTYPE = 0x7d4;
        public const int CERTINFO_FINGERPRINT_SHA1 = 0x7d5;
        public const int CERTINFO_FINGERPRINT_SHA2 = 0x7d6;
        public const int CERTINFO_FINGERPRINT_SHAng = 0x7d7;
        public const int CERTINFO_CURRENT_CERTIFICATE = 0x7d8;
        public const int CERTINFO_TRUSTED_USAGE = 0x7d9;
        public const int CERTINFO_TRUSTED_IMPLICIT = 0x7da;
        public const int CERTINFO_SIGNATURELEVEL = 0x7db;
        public const int CERTINFO_VERSION = 0x7dc;
        public const int CERTINFO_SERIALNUMBER = 0x7dd;
        public const int CERTINFO_SUBJECTPUBLICKEYINFO = 0x7de;
        public const int CERTINFO_CERTIFICATE = 0x7df;
        public const int CERTINFO_USERCERTIFICATE = 0x7df;
        public const int CERTINFO_CACERTIFICATE = 0x7e0;
        public const int CERTINFO_ISSUERNAME = 0x7e1;
        public const int CERTINFO_VALIDFROM = 0x7e2;
        public const int CERTINFO_VALIDTO = 0x7e3;
        public const int CERTINFO_SUBJECTNAME = 0x7e4;
        public const int CERTINFO_ISSUERUNIQUEID = 0x7e5;
        public const int CERTINFO_SUBJECTUNIQUEID = 0x7e6;
        public const int CERTINFO_CERTREQUEST = 0x7e7;
        public const int CERTINFO_THISUPDATE = 0x7e8;
        public const int CERTINFO_NEXTUPDATE = 0x7e9;
        public const int CERTINFO_REVOCATIONDATE = 0x7ea;
        public const int CERTINFO_REVOCATIONSTATUS = 0x7eb;
        public const int CERTINFO_CERTSTATUS = 0x7ec;
        public const int CERTINFO_DN = 0x7ed;
        public const int CERTINFO_PKIUSER_ID = 0x7ee;
        public const int CERTINFO_PKIUSER_ISSUEPASSWORD = 0x7ef;
        public const int CERTINFO_PKIUSER_REVPASSWORD = 0x7f0;
        public const int CERTINFO_PKIUSER_RA = 0x7f1;
        public const int CERTINFO_COUNTRYNAME = 0x834;
        public const int CERTINFO_STATEORPROVINCENAME = 0x835;
        public const int CERTINFO_LOCALITYNAME = 0x836;
        public const int CERTINFO_ORGANIZATIONNAME = 0x837;
        public const int CERTINFO_ORGANISATIONNAME = 0x837;
        public const int CERTINFO_ORGANIZATIONALUNITNAME = 0x838;
        public const int CERTINFO_ORGANISATIONALUNITNAME = 0x838;
        public const int CERTINFO_COMMONNAME = 0x839;
        public const int CERTINFO_OTHERNAME_TYPEID = 0x83a;
        public const int CERTINFO_OTHERNAME_VALUE = 0x83b;
        public const int CERTINFO_RFC822NAME = 0x83c;
        public const int CERTINFO_EMAIL = 0x83c;
        public const int CERTINFO_DNSNAME = 0x83d;
        public const int CERTINFO_DIRECTORYNAME = 0x83e;
        public const int CERTINFO_EDIPARTYNAME_NAMEASSIGNER = 0x83f;
        public const int CERTINFO_EDIPARTYNAME_PARTYNAME = 0x840;
        public const int CERTINFO_UNIFORMRESOURCEIDENTIFIER = 0x841;
        public const int CERTINFO_URL = 0x841;
        public const int CERTINFO_IPADDRESS = 0x842;
        public const int CERTINFO_REGISTEREDID = 0x843;
        public const int CERTINFO_CHALLENGEPASSWORD = 0x898;
        public const int CERTINFO_CRLEXTREASON = 0x899;
        public const int CERTINFO_KEYFEATURES = 0x89a;
        public const int CERTINFO_AUTHORITYINFOACCESS = 0x89b;
        public const int CERTINFO_AUTHORITYINFO_RTCS = 0x89c;
        public const int CERTINFO_AUTHORITYINFO_OCSP = 0x89d;
        public const int CERTINFO_AUTHORITYINFO_CAISSUERS = 0x89e;
        public const int CERTINFO_AUTHORITYINFO_CERTSTORE = 0x89f;
        public const int CERTINFO_AUTHORITYINFO_CRLS = 0x8a0;
        public const int CERTINFO_BIOMETRICINFO = 0x8a1;
        public const int CERTINFO_BIOMETRICINFO_TYPE = 0x8a2;
        public const int CERTINFO_BIOMETRICINFO_HASHALGO = 0x8a3;
        public const int CERTINFO_BIOMETRICINFO_HASH = 0x8a4;
        public const int CERTINFO_BIOMETRICINFO_URL = 0x8a5;
        public const int CERTINFO_QCSTATEMENT = 0x8a6;
        public const int CERTINFO_QCSTATEMENT_SEMANTICS = 0x8a7;
        public const int CERTINFO_QCSTATEMENT_REGISTRATIONAUTHORITY = 0x8a8;
        public const int CERTINFO_IPADDRESSBLOCKS = 0x8a9;
        public const int CERTINFO_IPADDRESSBLOCKS_ADDRESSFAMILY = 0x8aa;
        public const int CERTINFO_IPADDRESSBLOCKS_PREFIX = 0x8ab;
        public const int CERTINFO_IPADDRESSBLOCKS_MIN = 0x8ac;
        public const int CERTINFO_IPADDRESSBLOCKS_MAX = 0x8ad;
        public const int CERTINFO_AUTONOMOUSSYSIDS = 0x8ae;
        public const int CERTINFO_AUTONOMOUSSYSIDS_ASNUM_ID = 0x8af;
        public const int CERTINFO_AUTONOMOUSSYSIDS_ASNUM_MIN = 0x8b0;
        public const int CERTINFO_AUTONOMOUSSYSIDS_ASNUM_MAX = 0x8b1;
        public const int CERTINFO_OCSP_NONCE = 0x8b2;
        public const int CERTINFO_OCSP_RESPONSE = 0x8b3;
        public const int CERTINFO_OCSP_RESPONSE_OCSP = 0x8b4;
        public const int CERTINFO_OCSP_NOCHECK = 0x8b5;
        public const int CERTINFO_OCSP_ARCHIVECUTOFF = 0x8b6;
        public const int CERTINFO_SUBJECTINFOACCESS = 0x8b7;
        public const int CERTINFO_SUBJECTINFO_TIMESTAMPING = 0x8b8;
        public const int CERTINFO_SUBJECTINFO_CAREPOSITORY = 0x8b9;
        public const int CERTINFO_SUBJECTINFO_SIGNEDOBJECTREPOSITORY = 0x8ba;
        public const int CERTINFO_SUBJECTINFO_RPKIMANIFEST = 0x8bb;
        public const int CERTINFO_SUBJECTINFO_SIGNEDOBJECT = 0x8bc;
        public const int CERTINFO_SIGG_DATEOFCERTGEN = 0x8bd;
        public const int CERTINFO_SIGG_PROCURATION = 0x8be;
        public const int CERTINFO_SIGG_PROCURE_COUNTRY = 0x8bf;
        public const int CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION = 0x8c0;
        public const int CERTINFO_SIGG_PROCURE_SIGNINGFOR = 0x8c1;
        public const int CERTINFO_SIGG_ADMISSIONS = 0x8c2;
        public const int CERTINFO_SIGG_ADMISSIONS_AUTHORITY = 0x8c3;
        public const int CERTINFO_SIGG_ADMISSIONS_NAMINGAUTHID = 0x8c4;
        public const int CERTINFO_SIGG_ADMISSIONS_NAMINGAUTHURL = 0x8c5;
        public const int CERTINFO_SIGG_ADMISSIONS_NAMINGAUTHTEXT = 0x8c6;
        public const int CERTINFO_SIGG_ADMISSIONS_PROFESSIONITEM = 0x8c7;
        public const int CERTINFO_SIGG_ADMISSIONS_PROFESSIONOID = 0x8c8;
        public const int CERTINFO_SIGG_ADMISSIONS_REGISTRATIONNUMBER = 0x8c9;
        public const int CERTINFO_SIGG_MONETARYLIMIT = 0x8ca;
        public const int CERTINFO_SIGG_MONETARY_CURRENCY = 0x8cb;
        public const int CERTINFO_SIGG_MONETARY_AMOUNT = 0x8cc;
        public const int CERTINFO_SIGG_MONETARY_EXPONENT = 0x8cd;
        public const int CERTINFO_SIGG_DECLARATIONOFMAJORITY = 0x8ce;
        public const int CERTINFO_SIGG_DECLARATIONOFMAJORITY_COUNTRY = 0x8cf;
        public const int CERTINFO_SIGG_RESTRICTION = 0x8d0;
        public const int CERTINFO_SIGG_CERTHASH = 0x8d1;
        public const int CERTINFO_SIGG_ADDITIONALINFORMATION = 0x8d2;
        public const int CERTINFO_STRONGEXTRANET = 0x8d3;
        public const int CERTINFO_STRONGEXTRANET_ZONE = 0x8d4;
        public const int CERTINFO_STRONGEXTRANET_ID = 0x8d5;
        public const int CERTINFO_SUBJECTDIRECTORYATTRIBUTES = 0x8d6;
        public const int CERTINFO_SUBJECTDIR_TYPE = 0x8d7;
        public const int CERTINFO_SUBJECTDIR_VALUES = 0x8d8;
        public const int CERTINFO_SUBJECTKEYIDENTIFIER = 0x8d9;
        public const int CERTINFO_KEYUSAGE = 0x8da;
        public const int CERTINFO_PRIVATEKEYUSAGEPERIOD = 0x8db;
        public const int CERTINFO_PRIVATEKEY_NOTBEFORE = 0x8dc;
        public const int CERTINFO_PRIVATEKEY_NOTAFTER = 0x8dd;
        public const int CERTINFO_SUBJECTALTNAME = 0x8de;
        public const int CERTINFO_ISSUERALTNAME = 0x8df;
        public const int CERTINFO_BASICCONSTRAINTS = 0x8e0;
        public const int CERTINFO_CA = 0x8e1;
        public const int CERTINFO_AUTHORITY = 0x8e1;
        public const int CERTINFO_PATHLENCONSTRAINT = 0x8e2;
        public const int CERTINFO_CRLNUMBER = 0x8e3;
        public const int CERTINFO_CRLREASON = 0x8e4;
        public const int CERTINFO_HOLDINSTRUCTIONCODE = 0x8e5;
        public const int CERTINFO_INVALIDITYDATE = 0x8e6;
        public const int CERTINFO_DELTACRLINDICATOR = 0x8e7;
        public const int CERTINFO_ISSUINGDISTRIBUTIONPOINT = 0x8e8;
        public const int CERTINFO_ISSUINGDIST_FULLNAME = 0x8e9;
        public const int CERTINFO_ISSUINGDIST_USERCERTSONLY = 0x8ea;
        public const int CERTINFO_ISSUINGDIST_CACERTSONLY = 0x8eb;
        public const int CERTINFO_ISSUINGDIST_SOMEREASONSONLY = 0x8ec;
        public const int CERTINFO_ISSUINGDIST_INDIRECTCRL = 0x8ed;
        public const int CERTINFO_CERTIFICATEISSUER = 0x8ee;
        public const int CERTINFO_NAMECONSTRAINTS = 0x8ef;
        public const int CERTINFO_PERMITTEDSUBTREES = 0x8f0;
        public const int CERTINFO_EXCLUDEDSUBTREES = 0x8f1;
        public const int CERTINFO_CRLDISTRIBUTIONPOINT = 0x8f2;
        public const int CERTINFO_CRLDIST_FULLNAME = 0x8f3;
        public const int CERTINFO_CRLDIST_REASONS = 0x8f4;
        public const int CERTINFO_CRLDIST_CRLISSUER = 0x8f5;
        public const int CERTINFO_CERTIFICATEPOLICIES = 0x8f6;
        public const int CERTINFO_CERTPOLICYID = 0x8f7;
        public const int CERTINFO_CERTPOLICY_CPSURI = 0x8f8;
        public const int CERTINFO_CERTPOLICY_ORGANIZATION = 0x8f9;
        public const int CERTINFO_CERTPOLICY_NOTICENUMBERS = 0x8fa;
        public const int CERTINFO_CERTPOLICY_EXPLICITTEXT = 0x8fb;
        public const int CERTINFO_POLICYMAPPINGS = 0x8fc;
        public const int CERTINFO_ISSUERDOMAINPOLICY = 0x8fd;
        public const int CERTINFO_SUBJECTDOMAINPOLICY = 0x8fe;
        public const int CERTINFO_AUTHORITYKEYIDENTIFIER = 0x8ff;
        public const int CERTINFO_AUTHORITY_KEYIDENTIFIER = 0x900;
        public const int CERTINFO_AUTHORITY_CERTISSUER = 0x901;
        public const int CERTINFO_AUTHORITY_CERTSERIALNUMBER = 0x902;
        public const int CERTINFO_POLICYCONSTRAINTS = 0x903;
        public const int CERTINFO_REQUIREEXPLICITPOLICY = 0x904;
        public const int CERTINFO_INHIBITPOLICYMAPPING = 0x905;
        public const int CERTINFO_EXTKEYUSAGE = 0x906;
        public const int CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING = 0x907;
        public const int CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING = 0x908;
        public const int CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING = 0x909;
        public const int CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING = 0x90a;
        public const int CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO = 0x90b;
        public const int CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM = 0x90c;
        public const int CERTINFO_EXTKEY_SERVERAUTH = 0x90d;
        public const int CERTINFO_EXTKEY_CLIENTAUTH = 0x90e;
        public const int CERTINFO_EXTKEY_CODESIGNING = 0x90f;
        public const int CERTINFO_EXTKEY_EMAILPROTECTION = 0x910;
        public const int CERTINFO_EXTKEY_IPSECENDSYSTEM = 0x911;
        public const int CERTINFO_EXTKEY_IPSECTUNNEL = 0x912;
        public const int CERTINFO_EXTKEY_IPSECUSER = 0x913;
        public const int CERTINFO_EXTKEY_TIMESTAMPING = 0x914;
        public const int CERTINFO_EXTKEY_OCSPSIGNING = 0x915;
        public const int CERTINFO_EXTKEY_DIRECTORYSERVICE = 0x916;
        public const int CERTINFO_EXTKEY_ANYKEYUSAGE = 0x917;
        public const int CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO = 0x918;
        public const int CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA = 0x919;
        public const int CERTINFO_CRLSTREAMIDENTIFIER = 0x91a;
        public const int CERTINFO_FRESHESTCRL = 0x91b;
        public const int CERTINFO_FRESHESTCRL_FULLNAME = 0x91c;
        public const int CERTINFO_FRESHESTCRL_REASONS = 0x91d;
        public const int CERTINFO_FRESHESTCRL_CRLISSUER = 0x91e;
        public const int CERTINFO_ORDEREDLIST = 0x91f;
        public const int CERTINFO_BASEUPDATETIME = 0x920;
        public const int CERTINFO_DELTAINFO = 0x921;
        public const int CERTINFO_DELTAINFO_LOCATION = 0x922;
        public const int CERTINFO_DELTAINFO_NEXTDELTA = 0x923;
        public const int CERTINFO_INHIBITANYPOLICY = 0x924;
        public const int CERTINFO_TOBEREVOKED = 0x925;
        public const int CERTINFO_TOBEREVOKED_CERTISSUER = 0x926;
        public const int CERTINFO_TOBEREVOKED_REASONCODE = 0x927;
        public const int CERTINFO_TOBEREVOKED_REVOCATIONTIME = 0x928;
        public const int CERTINFO_TOBEREVOKED_CERTSERIALNUMBER = 0x929;
        public const int CERTINFO_REVOKEDGROUPS = 0x92a;
        public const int CERTINFO_REVOKEDGROUPS_CERTISSUER = 0x92b;
        public const int CERTINFO_REVOKEDGROUPS_REASONCODE = 0x92c;
        public const int CERTINFO_REVOKEDGROUPS_INVALIDITYDATE = 0x92d;
        public const int CERTINFO_REVOKEDGROUPS_STARTINGNUMBER = 0x92e;
        public const int CERTINFO_REVOKEDGROUPS_ENDINGNUMBER = 0x92f;
        public const int CERTINFO_EXPIREDCERTSONCRL = 0x930;
        public const int CERTINFO_AAISSUINGDISTRIBUTIONPOINT = 0x931;
        public const int CERTINFO_AAISSUINGDIST_FULLNAME = 0x932;
        public const int CERTINFO_AAISSUINGDIST_SOMEREASONSONLY = 0x933;
        public const int CERTINFO_AAISSUINGDIST_INDIRECTCRL = 0x934;
        public const int CERTINFO_AAISSUINGDIST_USERATTRCERTS = 0x935;
        public const int CERTINFO_AAISSUINGDIST_AACERTS = 0x936;
        public const int CERTINFO_AAISSUINGDIST_SOACERTS = 0x937;
        public const int CERTINFO_NS_CERTTYPE = 0x938;
        public const int CERTINFO_NS_BASEURL = 0x939;
        public const int CERTINFO_NS_REVOCATIONURL = 0x93a;
        public const int CERTINFO_NS_CAREVOCATIONURL = 0x93b;
        public const int CERTINFO_NS_CERTRENEWALURL = 0x93c;
        public const int CERTINFO_NS_CAPOLICYURL = 0x93d;
        public const int CERTINFO_NS_SSLSERVERNAME = 0x93e;
        public const int CERTINFO_NS_COMMENT = 0x93f;
        public const int CERTINFO_SET_HASHEDROOTKEY = 0x940;
        public const int CERTINFO_SET_ROOTKEYTHUMBPRINT = 0x941;
        public const int CERTINFO_SET_CERTIFICATETYPE = 0x942;
        public const int CERTINFO_SET_MERCHANTDATA = 0x943;
        public const int CERTINFO_SET_MERID = 0x944;
        public const int CERTINFO_SET_MERACQUIRERBIN = 0x945;
        public const int CERTINFO_SET_MERCHANTLANGUAGE = 0x946;
        public const int CERTINFO_SET_MERCHANTNAME = 0x947;
        public const int CERTINFO_SET_MERCHANTCITY = 0x948;
        public const int CERTINFO_SET_MERCHANTSTATEPROVINCE = 0x949;
        public const int CERTINFO_SET_MERCHANTPOSTALCODE = 0x94a;
        public const int CERTINFO_SET_MERCHANTCOUNTRYNAME = 0x94b;
        public const int CERTINFO_SET_MERCOUNTRY = 0x94c;
        public const int CERTINFO_SET_MERAUTHFLAG = 0x94d;
        public const int CERTINFO_SET_CERTCARDREQUIRED = 0x94e;
        public const int CERTINFO_SET_TUNNELING = 0x94f;
        public const int CERTINFO_SET_TUNNELLING = 0x94f;
        public const int CERTINFO_SET_TUNNELINGFLAG = 0x950;
        public const int CERTINFO_SET_TUNNELLINGFLAG = 0x950;
        public const int CERTINFO_SET_TUNNELINGALGID = 0x951;
        public const int CERTINFO_SET_TUNNELLINGALGID = 0x951;
        public const int CERTINFO_CMS_CONTENTTYPE = 0x9c4;
        public const int CERTINFO_CMS_MESSAGEDIGEST = 0x9c5;
        public const int CERTINFO_CMS_SIGNINGTIME = 0x9c6;
        public const int CERTINFO_CMS_COUNTERSIGNATURE = 0x9c7;
        public const int CERTINFO_CMS_SIGNINGDESCRIPTION = 0x9c8;
        public const int CERTINFO_CMS_SMIMECAPABILITIES = 0x9c9;
        public const int CERTINFO_CMS_SMIMECAP_3DES = 0x9ca;
        public const int CERTINFO_CMS_SMIMECAP_AES = 0x9cb;
        public const int CERTINFO_CMS_SMIMECAP_CAST128 = 0x9cc;
        public const int CERTINFO_CMS_SMIMECAP_SHAng = 0x9cd;
        public const int CERTINFO_CMS_SMIMECAP_SHA2 = 0x9ce;
        public const int CERTINFO_CMS_SMIMECAP_SHA1 = 0x9cf;
        public const int CERTINFO_CMS_SMIMECAP_HMAC_SHAng = 0x9d0;
        public const int CERTINFO_CMS_SMIMECAP_HMAC_SHA2 = 0x9d1;
        public const int CERTINFO_CMS_SMIMECAP_HMAC_SHA1 = 0x9d2;
        public const int CERTINFO_CMS_SMIMECAP_AUTHENC256 = 0x9d3;
        public const int CERTINFO_CMS_SMIMECAP_AUTHENC128 = 0x9d4;
        public const int CERTINFO_CMS_SMIMECAP_RSA_SHAng = 0x9d5;
        public const int CERTINFO_CMS_SMIMECAP_RSA_SHA2 = 0x9d6;
        public const int CERTINFO_CMS_SMIMECAP_RSA_SHA1 = 0x9d7;
        public const int CERTINFO_CMS_SMIMECAP_DSA_SHA1 = 0x9d8;
        public const int CERTINFO_CMS_SMIMECAP_ECDSA_SHAng = 0x9d9;
        public const int CERTINFO_CMS_SMIMECAP_ECDSA_SHA2 = 0x9da;
        public const int CERTINFO_CMS_SMIMECAP_ECDSA_SHA1 = 0x9db;
        public const int CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA = 0x9dc;
        public const int CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY = 0x9dd;
        public const int CERTINFO_CMS_SMIMECAP_PREFERBINARYINSIDE = 0x9de;
        public const int CERTINFO_CMS_RECEIPTREQUEST = 0x9df;
        public const int CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER = 0x9e0;
        public const int CERTINFO_CMS_RECEIPT_FROM = 0x9e1;
        public const int CERTINFO_CMS_RECEIPT_TO = 0x9e2;
        public const int CERTINFO_CMS_SECURITYLABEL = 0x9e3;
        public const int CERTINFO_CMS_SECLABEL_POLICY = 0x9e4;
        public const int CERTINFO_CMS_SECLABEL_CLASSIFICATION = 0x9e5;
        public const int CERTINFO_CMS_SECLABEL_PRIVACYMARK = 0x9e6;
        public const int CERTINFO_CMS_SECLABEL_CATTYPE = 0x9e7;
        public const int CERTINFO_CMS_SECLABEL_CATVALUE = 0x9e8;
        public const int CERTINFO_CMS_MLEXPANSIONHISTORY = 0x9e9;
        public const int CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER = 0x9ea;
        public const int CERTINFO_CMS_MLEXP_TIME = 0x9eb;
        public const int CERTINFO_CMS_MLEXP_NONE = 0x9ec;
        public const int CERTINFO_CMS_MLEXP_INSTEADOF = 0x9ed;
        public const int CERTINFO_CMS_MLEXP_INADDITIONTO = 0x9ee;
        public const int CERTINFO_CMS_CONTENTHINTS = 0x9ef;
        public const int CERTINFO_CMS_CONTENTHINT_DESCRIPTION = 0x9f0;
        public const int CERTINFO_CMS_CONTENTHINT_TYPE = 0x9f1;
        public const int CERTINFO_CMS_EQUIVALENTLABEL = 0x9f2;
        public const int CERTINFO_CMS_EQVLABEL_POLICY = 0x9f3;
        public const int CERTINFO_CMS_EQVLABEL_CLASSIFICATION = 0x9f4;
        public const int CERTINFO_CMS_EQVLABEL_PRIVACYMARK = 0x9f5;
        public const int CERTINFO_CMS_EQVLABEL_CATTYPE = 0x9f6;
        public const int CERTINFO_CMS_EQVLABEL_CATVALUE = 0x9f7;
        public const int CERTINFO_CMS_SIGNINGCERTIFICATE = 0x9f8;
        public const int CERTINFO_CMS_SIGNINGCERT_ESSCERTID = 0x9f9;
        public const int CERTINFO_CMS_SIGNINGCERT_POLICIES = 0x9fa;
        public const int CERTINFO_CMS_SIGNINGCERTIFICATEV2 = 0x9fb;
        public const int CERTINFO_CMS_SIGNINGCERTV2_ESSCERTIDV2 = 0x9fc;
        public const int CERTINFO_CMS_SIGNINGCERTV2_POLICIES = 0x9fd;
        public const int CERTINFO_CMS_SIGNATUREPOLICYID = 0x9fe;
        public const int CERTINFO_CMS_SIGPOLICYID = 0x9ff;
        public const int CERTINFO_CMS_SIGPOLICYHASH = 0xa00;
        public const int CERTINFO_CMS_SIGPOLICY_CPSURI = 0xa01;
        public const int CERTINFO_CMS_SIGPOLICY_ORGANIZATION = 0xa02;
        public const int CERTINFO_CMS_SIGPOLICY_NOTICENUMBERS = 0xa03;
        public const int CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT = 0xa04;
        public const int CERTINFO_CMS_SIGTYPEIDENTIFIER = 0xa05;
        public const int CERTINFO_CMS_SIGTYPEID_ORIGINATORSIG = 0xa06;
        public const int CERTINFO_CMS_SIGTYPEID_DOMAINSIG = 0xa07;
        public const int CERTINFO_CMS_SIGTYPEID_ADDITIONALATTRIBUTES = 0xa08;
        public const int CERTINFO_CMS_SIGTYPEID_REVIEWSIG = 0xa09;
        public const int CERTINFO_CMS_NONCE = 0xa0a;
        public const int CERTINFO_SCEP_MESSAGETYPE = 0xa0b;
        public const int CERTINFO_SCEP_PKISTATUS = 0xa0c;
        public const int CERTINFO_SCEP_FAILINFO = 0xa0d;
        public const int CERTINFO_SCEP_SENDERNONCE = 0xa0e;
        public const int CERTINFO_SCEP_RECIPIENTNONCE = 0xa0f;
        public const int CERTINFO_SCEP_TRANSACTIONID = 0xa10;
        public const int CERTINFO_CMS_SPCAGENCYINFO = 0xa11;
        public const int CERTINFO_CMS_SPCAGENCYURL = 0xa12;
        public const int CERTINFO_CMS_SPCSTATEMENTTYPE = 0xa13;
        public const int CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING = 0xa14;
        public const int CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING = 0xa15;
        public const int CERTINFO_CMS_SPCOPUSINFO = 0xa16;
        public const int CERTINFO_CMS_SPCOPUSINFO_NAME = 0xa17;
        public const int CERTINFO_CMS_SPCOPUSINFO_URL = 0xa18;
        public const int CERTINFO_LAST = 0xa19;
        public const int KEYINFO_FIRST = 0xbb8;
        public const int KEYINFO_QUERY = 0xbb9;
        public const int KEYINFO_QUERY_REQUESTS = 0xbba;
        public const int KEYINFO_LAST = 0xbbb;
        public const int DEVINFO_FIRST = 0xfa0;
        public const int DEVINFO_INITIALISE = 0xfa1;
        public const int DEVINFO_INITIALIZE = 0xfa1;
        public const int DEVINFO_AUTHENT_USER = 0xfa2;
        public const int DEVINFO_AUTHENT_SUPERVISOR = 0xfa3;
        public const int DEVINFO_SET_AUTHENT_USER = 0xfa4;
        public const int DEVINFO_SET_AUTHENT_SUPERVISOR = 0xfa5;
        public const int DEVINFO_ZEROISE = 0xfa6;
        public const int DEVINFO_ZEROIZE = 0xfa6;
        public const int DEVINFO_LOGGEDIN = 0xfa7;
        public const int DEVINFO_LABEL = 0xfa8;
        public const int DEVINFO_LAST = 0xfa9;
        public const int ENVINFO_FIRST = 0x1388;
        public const int ENVINFO_DATASIZE = 0x1389;
        public const int ENVINFO_COMPRESSION = 0x138a;
        public const int ENVINFO_CONTENTTYPE = 0x138b;
        public const int ENVINFO_DETACHEDSIGNATURE = 0x138c;
        public const int ENVINFO_SIGNATURE_RESULT = 0x138d;
        public const int ENVINFO_INTEGRITY = 0x138e;
        public const int ENVINFO_PASSWORD = 0x138f;
        public const int ENVINFO_KEY = 0x1390;
        public const int ENVINFO_SIGNATURE = 0x1391;
        public const int ENVINFO_SIGNATURE_EXTRADATA = 0x1392;
        public const int ENVINFO_RECIPIENT = 0x1393;
        public const int ENVINFO_PUBLICKEY = 0x1394;
        public const int ENVINFO_PRIVATEKEY = 0x1395;
        public const int ENVINFO_PRIVATEKEY_LABEL = 0x1396;
        public const int ENVINFO_ORIGINATOR = 0x1397;
        public const int ENVINFO_SESSIONKEY = 0x1398;
        public const int ENVINFO_HASH = 0x1399;
        public const int ENVINFO_TIMESTAMP = 0x139a;
        public const int ENVINFO_KEYSET_SIGCHECK = 0x139b;
        public const int ENVINFO_KEYSET_ENCRYPT = 0x139c;
        public const int ENVINFO_KEYSET_DECRYPT = 0x139d;
        public const int ENVINFO_LAST = 0x139e;
        public const int SESSINFO_FIRST = 0x1770;
        public const int SESSINFO_ACTIVE = 0x1771;
        public const int SESSINFO_CONNECTIONACTIVE = 0x1772;
        public const int SESSINFO_USERNAME = 0x1773;
        public const int SESSINFO_PASSWORD = 0x1774;
        public const int SESSINFO_PRIVATEKEY = 0x1775;
        public const int SESSINFO_KEYSET = 0x1776;
        public const int SESSINFO_AUTHRESPONSE = 0x1777;
        public const int SESSINFO_SERVER_NAME = 0x1778;
        public const int SESSINFO_SERVER_PORT = 0x1779;
        public const int SESSINFO_SERVER_FINGERPRINT_SHA1 = 0x177a;
        public const int SESSINFO_CLIENT_NAME = 0x177b;
        public const int SESSINFO_CLIENT_PORT = 0x177c;
        public const int SESSINFO_SESSION = 0x177d;
        public const int SESSINFO_NETWORKSOCKET = 0x177e;
        public const int SESSINFO_VERSION = 0x177f;
        public const int SESSINFO_REQUEST = 0x1780;
        public const int SESSINFO_RESPONSE = 0x1781;
        public const int SESSINFO_CACERTIFICATE = 0x1782;
        public const int SESSINFO_CMP_REQUESTTYPE = 0x1783;
        public const int SESSINFO_CMP_PRIVKEYSET = 0x1784;
        public const int SESSINFO_SSH_CHANNEL = 0x1785;
        public const int SESSINFO_SSH_CHANNEL_TYPE = 0x1786;
        public const int SESSINFO_SSH_CHANNEL_ARG1 = 0x1787;
        public const int SESSINFO_SSH_CHANNEL_ARG2 = 0x1788;
        public const int SESSINFO_SSH_CHANNEL_ACTIVE = 0x1789;
        public const int SESSINFO_SSL_OPTIONS = 0x178a;
        public const int SESSINFO_TSP_MSGIMPRINT = 0x178b;
        public const int SESSINFO_LAST = 0x178c;
        public const int USERINFO_FIRST = 0x1b58;
        public const int USERINFO_PASSWORD = 0x1b59;
        public const int USERINFO_CAKEY_CERTSIGN = 0x1b5a;
        public const int USERINFO_CAKEY_CRLSIGN = 0x1b5b;
        public const int USERINFO_CAKEY_RTCSSIGN = 0x1b5c;
        public const int USERINFO_CAKEY_OCSPSIGN = 0x1b5d;
        public const int USERINFO_LAST = 0x1b5e;
        public const int ATTRIBUTE_LAST = 0x1b5e;
        public const int KEYUSAGE_NONE = 0;
        public const int KEYUSAGE_DIGITALSIGNATURE = 1;
        public const int KEYUSAGE_NONREPUDIATION = 2;
        public const int KEYUSAGE_KEYENCIPHERMENT = 4;
        public const int KEYUSAGE_DATAENCIPHERMENT = 8;
        public const int KEYUSAGE_KEYAGREEMENT = 0x10;
        public const int KEYUSAGE_KEYCERTSIGN = 0x20;
        public const int KEYUSAGE_CRLSIGN = 0x40;
        public const int KEYUSAGE_ENCIPHERONLY = 0x80;
        public const int KEYUSAGE_DECIPHERONLY = 0x100;
        public const int KEYUSAGE_LAST = 0x200;
        public const int CRLREASON_UNSPECIFIED = 0;
        public const int CRLREASON_KEYCOMPROMISE = 1;
        public const int CRLREASON_CACOMPROMISE = 2;
        public const int CRLREASON_AFFILIATIONCHANGED = 3;
        public const int CRLREASON_SUPERSEDED = 4;
        public const int CRLREASON_CESSATIONOFOPERATION = 5;
        public const int CRLREASON_CERTIFICATEHOLD = 6;
        public const int CRLREASON_REMOVEFROMCRL = 8;
        public const int CRLREASON_PRIVILEGEWITHDRAWN = 9;
        public const int CRLREASON_AACOMPROMISE = 10;
        public const int CRLREASON_LAST = 11;
        public const int CRLREASON_NEVERVALID = 20;
        public const int CRLEXTREASON_LAST = 0x15;
        public const int CRLREASONFLAG_UNUSED = 1;
        public const int CRLREASONFLAG_KEYCOMPROMISE = 2;
        public const int CRLREASONFLAG_CACOMPROMISE = 4;
        public const int CRLREASONFLAG_AFFILIATIONCHANGED = 8;
        public const int CRLREASONFLAG_SUPERSEDED = 0x10;
        public const int CRLREASONFLAG_CESSATIONOFOPERATION = 0x20;
        public const int CRLREASONFLAG_CERTIFICATEHOLD = 0x40;
        public const int CRLREASONFLAG_LAST = 0x80;
        public const int HOLDINSTRUCTION_NONE = 0;
        public const int HOLDINSTRUCTION_CALLISSUER = 1;
        public const int HOLDINSTRUCTION_REJECT = 2;
        public const int HOLDINSTRUCTION_PICKUPTOKEN = 3;
        public const int HOLDINSTRUCTION_LAST = 4;
        public const int COMPLIANCELEVEL_OBLIVIOUS = 0;
        public const int COMPLIANCELEVEL_REDUCED = 1;
        public const int COMPLIANCELEVEL_STANDARD = 2;
        public const int COMPLIANCELEVEL_PKIX_PARTIAL = 3;
        public const int COMPLIANCELEVEL_PKIX_FULL = 4;
        public const int COMPLIANCELEVEL_LAST = 5;
        public const int NS_CERTTYPE_SSLCLIENT = 1;
        public const int NS_CERTTYPE_SSLSERVER = 2;
        public const int NS_CERTTYPE_SMIME = 4;
        public const int NS_CERTTYPE_OBJECTSIGNING = 8;
        public const int NS_CERTTYPE_RESERVED = 0x10;
        public const int NS_CERTTYPE_SSLCA = 0x20;
        public const int NS_CERTTYPE_SMIMECA = 0x40;
        public const int NS_CERTTYPE_OBJECTSIGNINGCA = 0x80;
        public const int NS_CERTTYPE_LAST = 0x100;
        public const int SET_CERTTYPE_CARD = 1;
        public const int SET_CERTTYPE_MER = 2;
        public const int SET_CERTTYPE_PGWY = 4;
        public const int SET_CERTTYPE_CCA = 8;
        public const int SET_CERTTYPE_MCA = 0x10;
        public const int SET_CERTTYPE_PCA = 0x20;
        public const int SET_CERTTYPE_GCA = 0x40;
        public const int SET_CERTTYPE_BCA = 0x80;
        public const int SET_CERTTYPE_RCA = 0x100;
        public const int SET_CERTTYPE_ACQ = 0x200;
        public const int SET_CERTTYPE_LAST = 0x400;
        public const int CONTENT_NONE = 0;
        public const int CONTENT_DATA = 1;
        public const int CONTENT_SIGNEDDATA = 2;
        public const int CONTENT_ENVELOPEDDATA = 3;
        public const int CONTENT_SIGNEDANDENVELOPEDDATA = 4;
        public const int CONTENT_DIGESTEDDATA = 5;
        public const int CONTENT_ENCRYPTEDDATA = 6;
        public const int CONTENT_COMPRESSEDDATA = 7;
        public const int CONTENT_AUTHDATA = 8;
        public const int CONTENT_AUTHENVDATA = 9;
        public const int CONTENT_TSTINFO = 10;
        public const int CONTENT_SPCINDIRECTDATACONTEXT = 11;
        public const int CONTENT_RTCSREQUEST = 12;
        public const int CONTENT_RTCSRESPONSE = 13;
        public const int CONTENT_RTCSRESPONSE_EXT = 14;
        public const int CONTENT_MRTD = 15;
        public const int CONTENT_LAST = 0x10;
        public const int CLASSIFICATION_UNMARKED = 0;
        public const int CLASSIFICATION_UNCLASSIFIED = 1;
        public const int CLASSIFICATION_RESTRICTED = 2;
        public const int CLASSIFICATION_CONFIDENTIAL = 3;
        public const int CLASSIFICATION_SECRET = 4;
        public const int CLASSIFICATION_TOP_SECRET = 5;
        public const int CLASSIFICATION_LAST = 0xff;
        public const int CERTSTATUS_VALID = 0;
        public const int CERTSTATUS_NOTVALID = 1;
        public const int CERTSTATUS_NONAUTHORITATIVE = 2;
        public const int CERTSTATUS_UNKNOWN = 3;
        public const int OCSPSTATUS_NOTREVOKED = 0;
        public const int OCSPSTATUS_REVOKED = 1;
        public const int OCSPSTATUS_UNKNOWN = 2;
        public const int SIGNATURELEVEL_NONE = 0;
        public const int SIGNATURELEVEL_SIGNERCERT = 1;
        public const int SIGNATURELEVEL_ALL = 2;
        public const int SIGNATURELEVEL_LAST = 3;
        public const int INTEGRITY_NONE = 0;
        public const int INTEGRITY_MACONLY = 1;
        public const int INTEGRITY_FULL = 2;
        public const int CERTFORMAT_NONE = 0;
        public const int CERTFORMAT_CERTIFICATE = 1;
        public const int CERTFORMAT_CERTCHAIN = 2;
        public const int CERTFORMAT_TEXT_CERTIFICATE = 3;
        public const int CERTFORMAT_TEXT_CERTCHAIN = 4;
        public const int CERTFORMAT_XML_CERTIFICATE = 5;
        public const int CERTFORMAT_XML_CERTCHAIN = 6;
        public const int CERTFORMAT_LAST = 7;
        public const int REQUESTTYPE_NONE = 0;
        public const int REQUESTTYPE_INITIALISATION = 1;
        public const int REQUESTTYPE_INITIALIZATION = 1;
        public const int REQUESTTYPE_CERTIFICATE = 2;
        public const int REQUESTTYPE_KEYUPDATE = 3;
        public const int REQUESTTYPE_REVOCATION = 4;
        public const int REQUESTTYPE_PKIBOOT = 5;
        public const int REQUESTTYPE_LAST = 6;
        public const int KEYID_NONE = 0;
        public const int KEYID_NAME = 1;
        public const int KEYID_URI = 2;
        public const int KEYID_EMAIL = 2;
        public const int KEYID_LAST = 3;
        public const int OBJECT_NONE = 0;
        public const int OBJECT_ENCRYPTED_KEY = 1;
        public const int OBJECT_PKCENCRYPTED_KEY = 2;
        public const int OBJECT_KEYAGREEMENT = 3;
        public const int OBJECT_SIGNATURE = 4;
        public const int OBJECT_LAST = 5;
        public const int ERRTYPE_NONE = 0;
        public const int ERRTYPE_ATTR_SIZE = 1;
        public const int ERRTYPE_ATTR_VALUE = 2;
        public const int ERRTYPE_ATTR_ABSENT = 3;
        public const int ERRTYPE_ATTR_PRESENT = 4;
        public const int ERRTYPE_CONSTRAINT = 5;
        public const int ERRTYPE_ISSUERCONSTRAINT = 6;
        public const int ERRTYPE_LAST = 7;
        public const int CERTACTION_NONE = 0;
        public const int CERTACTION_CREATE = 1;
        public const int CERTACTION_CONNECT = 2;
        public const int CERTACTION_DISCONNECT = 3;
        public const int CERTACTION_ERROR = 4;
        public const int CERTACTION_ADDUSER = 5;
        public const int CERTACTION_DELETEUSER = 6;
        public const int CERTACTION_REQUEST_CERT = 7;
        public const int CERTACTION_REQUEST_RENEWAL = 8;
        public const int CERTACTION_REQUEST_REVOCATION = 9;
        public const int CERTACTION_CERT_CREATION = 10;
        public const int CERTACTION_CERT_CREATION_COMPLETE = 11;
        public const int CERTACTION_CERT_CREATION_DROP = 12;
        public const int CERTACTION_CERT_CREATION_REVERSE = 13;
        public const int CERTACTION_RESTART_CLEANUP = 14;
        public const int CERTACTION_RESTART_REVOKE_CERT = 15;
        public const int CERTACTION_ISSUE_CERT = 0x10;
        public const int CERTACTION_ISSUE_CRL = 0x11;
        public const int CERTACTION_REVOKE_CERT = 0x12;
        public const int CERTACTION_EXPIRE_CERT = 0x13;
        public const int CERTACTION_CLEANUP = 20;
        public const int CERTACTION_LAST = 0x15;
        public const int SSLOPTION_NONE = 0;
        public const int SSLOPTION_MINVER_SSLV3 = 0;
        public const int SSLOPTION_MINVER_TLS10 = 1;
        public const int SSLOPTION_MINVER_TLS11 = 2;
        public const int SSLOPTION_MINVER_TLS12 = 3;
        public const int SSLOPTION_MINVER_TLS13 = 4;
        public const int SSLOPTION_MANUAL_CERTCHECK = 8;
        public const int SSLOPTION_DISABLE_NAMEVERIFY = 0x10;
        public const int SSLOPTION_DISABLE_CERTVERIFY = 0x20;
        public const int SSLOPTION_SUITEB_128 = 0x100;
        public const int SSLOPTION_SUITEB_256 = 0x200;
        public const int MAX_KEYSIZE = 0x100;
        public const int MAX_IVSIZE = 0x20;
        public const int MAX_PKCSIZE = 0x200;
        public const int MAX_PKCSIZE_ECC = 0x48;
        public const int MAX_HASHSIZE = 0x40;
        public const int MAX_TEXTSIZE = 0x40;
        public const int USE_DEFAULT = -100;
        public const int UNUSED = -101;
        public const int CURSOR_FIRST = -200;
        public const int CURSOR_PREVIOUS = -201;
        public const int CURSOR_NEXT = -202;
        public const int CURSOR_LAST = -203;
        public const int RANDOM_FASTPOLL = -300;
        public const int RANDOM_SLOWPOLL = -301;
        public const int KEYTYPE_PRIVATE = 0;
        public const int KEYTYPE_PUBLIC = 1;
        public const int KEYOPT_NONE = 0;
        public const int KEYOPT_READONLY = 1;
        public const int KEYOPT_CREATE = 2;
        public const int KEYOPT_LAST = 3;
        public const int ECCCURVE_NONE = 0;
        public const int ECCCURVE_P256 = 1;
        public const int ECCCURVE_P384 = 2;
        public const int ECCCURVE_P521 = 3;
        public const int ECCCURVE_BRAINPOOL_P256 = 4;
        public const int ECCCURVE_BRAINPOOL_P384 = 5;
        public const int ECCCURVE_BRAINPOOL_P512 = 6;
        public const int ECCCURVE_LAST = 7;
        public const int OK = 0;
        public const int ERROR_PARAM1 = -1;
        public const int ERROR_PARAM2 = -2;
        public const int ERROR_PARAM3 = -3;
        public const int ERROR_PARAM4 = -4;
        public const int ERROR_PARAM5 = -5;
        public const int ERROR_PARAM6 = -6;
        public const int ERROR_PARAM7 = -7;
        public const int ERROR_MEMORY = -10;
        public const int ERROR_NOTINITED = -11;
        public const int ERROR_INITED = -12;
        public const int ERROR_NOSECURE = -13;
        public const int ERROR_RANDOM = -14;
        public const int ERROR_FAILED = -15;
        public const int ERROR_INTERNAL = -16;
        public const int ERROR_NOTAVAIL = -20;
        public const int ERROR_PERMISSION = -21;
        public const int ERROR_WRONGKEY = -22;
        public const int ERROR_INCOMPLETE = -23;
        public const int ERROR_COMPLETE = -24;
        public const int ERROR_TIMEOUT = -25;
        public const int ERROR_INVALID = -26;
        public const int ERROR_SIGNALLED = -27;
        public const int ERROR_OVERFLOW = -30;
        public const int ERROR_UNDERFLOW = -31;
        public const int ERROR_BADDATA = -32;
        public const int ERROR_SIGNATURE = -33;
        public const int ERROR_OPEN = -40;
        public const int ERROR_READ = -41;
        public const int ERROR_WRITE = -42;
        public const int ERROR_NOTFOUND = -43;
        public const int ERROR_DUPLICATE = -44;
        public const int ENVELOPE_RESOURCE = -50;

        public const int CRYPT_KEYTYPE_PRIVATE = 0;
        public const int CRYPT_KEYTYPE_PUBLIC = 1;
        public const int CRYPT_ALGO_RSA = 101;


        // Methods
        public static void AddCertExtension(int certificate, string oid, int criticalFlag, byte[] extension)
        {
            AddCertExtension(certificate, oid, criticalFlag, extension, 0, (extension == null) ? 0 : extension.Length);
        }

        public static void AddCertExtension(int certificate, string oid, int criticalFlag, string extension)
        {
            AddCertExtension(certificate, oid, criticalFlag, (extension == null) ? null : new UTF8Encoding().GetBytes(extension), 0, (extension == null) ? 0 : new UTF8Encoding().GetByteCount(extension));
        }

        public static void AddCertExtension(int certificate, string oid, int criticalFlag, byte[] extension, int extensionOffset, int extensionLength)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(oid);
            GCHandle handle2 = new GCHandle();
            IntPtr bufferPtr = IntPtr.Zero;
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                checkIndices(extension, extensionOffset, extensionLength);
                getPointer(extension, extensionOffset, ref handle2, ref bufferPtr);
                processStatus(wrapped_AddCertExtension(certificate, zero, criticalFlag, bufferPtr, extensionLength));
            }
            finally
            {
                releasePointer(handle2);
                releasePointer(bufferHandle);
            }
        }

        public static void AddPrivateKey(int keyset, int cryptKey, string password)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(password);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                processStatus(wrapped_AddPrivateKey(keyset, cryptKey, zero));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static void AddPublicKey(int keyset, int certificate)
        {
            processStatus(wrapped_AddPublicKey(keyset, certificate));
        }

        public static void AddRandom(byte[] randomData)
        {
            AddRandom(randomData, 0, (randomData == null) ? 0 : randomData.Length);
        }

        public static void AddRandom(int pollType)
        {
            processStatus(wrapped_AddRandom(IntPtr.Zero, pollType));
        }

        public static void AddRandom(string randomData)
        {
            AddRandom((randomData == null) ? null : new UTF8Encoding().GetBytes(randomData), 0, (randomData == null) ? 0 : new UTF8Encoding().GetByteCount(randomData));
        }

        public static void AddRandom(byte[] randomData, int randomDataOffset, int randomDataLength)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(randomData, randomDataOffset, randomDataLength);
                getPointer(randomData, randomDataOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_AddRandom(zero, randomDataLength));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static void CAAddItem(int keyset, int certificate)
        {
            processStatus(wrapped_CAAddItem(keyset, certificate));
        }

        public static int CACertManagement(int action, int keyset, int caKey, int certRequest)
        {
            int num;
            IntPtr certificate = Marshal.AllocHGlobal(4);
            try
            {
                processStatus(wrapped_CACertManagement(certificate, action, keyset, caKey, certRequest));
                num = Marshal.ReadInt32(certificate);
            }
            finally
            {
                Marshal.FreeHGlobal(certificate);
            }
            return num;
        }

        public static void CADeleteItem(int keyset, int certType, int keyIDtype, string keyID)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(keyID);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                processStatus(wrapped_CADeleteItem(keyset, certType, keyIDtype, zero));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static int CAGetItem(int keyset, int certType, int keyIDtype, string keyID)
        {
            int num;
            IntPtr certificate = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(keyID);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                processStatus(wrapped_CAGetItem(keyset, certificate, certType, keyIDtype, zero));
                num = Marshal.ReadInt32(certificate);
            }
            finally
            {
                Marshal.FreeHGlobal(certificate);
                releasePointer(bufferHandle);
            }
            return num;
        }

        public static void CheckCert(int certificate, int sigCheckKey)
        {
            processStatus(wrapped_CheckCert(certificate, sigCheckKey));
        }

        private static void checkIndices(byte[] array, int sequenceOffset, int sequenceLength)
        {
            if (array == null)
            {
                if (sequenceOffset != 0)
                {
                    throw new IndexOutOfRangeException();
                }
            }
            else
            {
                int length = array.Length;
                if ((sequenceOffset < 0) || ((sequenceOffset >= length) || ((sequenceOffset + sequenceLength) > length)))
                {
                    throw new IndexOutOfRangeException();
                }
            }
        }

        public static void CheckSignature(byte[] signature, int sigCheckKey, int hashContext)
        {
            CheckSignature(signature, 0, (signature == null) ? 0 : signature.Length, sigCheckKey, hashContext);
        }

        public static void CheckSignature(string signature, int sigCheckKey, int hashContext)
        {
            CheckSignature((signature == null) ? null : new UTF8Encoding().GetBytes(signature), 0, (signature == null) ? 0 : new UTF8Encoding().GetByteCount(signature), sigCheckKey, hashContext);
        }

        public static void CheckSignature(byte[] signature, int signatureOffset, int signatureLength, int sigCheckKey, int hashContext)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(signature, signatureOffset, signatureLength);
                getPointer(signature, signatureOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_CheckSignature(zero, signatureLength, sigCheckKey, hashContext));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static int CheckSignatureEx(byte[] signature, int sigCheckKey, int hashContext) =>
            CheckSignatureEx(signature, 0, (signature == null) ? 0 : signature.Length, sigCheckKey, hashContext);

        public static int CheckSignatureEx(string signature, int sigCheckKey, int hashContext) =>
            CheckSignatureEx((signature == null) ? null : new UTF8Encoding().GetBytes(signature), 0, (signature == null) ? 0 : new UTF8Encoding().GetByteCount(signature), sigCheckKey, hashContext);

        public static int CheckSignatureEx(byte[] signature, int signatureOffset, int signatureLength, int sigCheckKey, int hashContext)
        {
            int num;
            IntPtr extraData = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(signature, signatureOffset, signatureLength);
                getPointer(signature, signatureOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_CheckSignatureEx(zero, signatureLength, sigCheckKey, hashContext, extraData));
                num = Marshal.ReadInt32(extraData);
            }
            finally
            {
                Marshal.FreeHGlobal(extraData);
                releasePointer(bufferHandle);
            }
            return num;
        }

        public static int CreateCert(int cryptUser, int certType)
        {
            int num;
            IntPtr certificate = Marshal.AllocHGlobal(4);
            try
            {
                processStatus(wrapped_CreateCert(certificate, cryptUser, certType));
                num = Marshal.ReadInt32(certificate);
            }
            finally
            {
                Marshal.FreeHGlobal(certificate);
            }
            return num;
        }

        public static int CreateContext(int cryptUser, int cryptAlgo)
        {
            int num;
            IntPtr cryptContext = Marshal.AllocHGlobal(4);
            try
            {
                processStatus(wrapped_CreateContext(cryptContext, cryptUser, cryptAlgo));
                num = Marshal.ReadInt32(cryptContext);
            }
            finally
            {
                Marshal.FreeHGlobal(cryptContext);
            }
            return num;
        }

        public static int CreateEnvelope(int cryptUser, int formatType)
        {
            int num;
            IntPtr envelope = Marshal.AllocHGlobal(4);
            try
            {
                processStatus(wrapped_CreateEnvelope(envelope, cryptUser, formatType));
                num = Marshal.ReadInt32(envelope);
            }
            finally
            {
                Marshal.FreeHGlobal(envelope);
            }
            return num;
        }

        public static int CreateSession(int cryptUser, int formatType)
        {
            int num;
            IntPtr session = Marshal.AllocHGlobal(4);
            try
            {
                processStatus(wrapped_CreateSession(session, cryptUser, formatType));
                num = Marshal.ReadInt32(session);
            }
            finally
            {
                Marshal.FreeHGlobal(session);
            }
            return num;
        }

        public static int CreateSignature(byte[] signature, int signatureMaxLength, int signContext, int hashContext) =>
            CreateSignature(signature, 0, signatureMaxLength, signContext, hashContext);

        public static int CreateSignature(byte[] signature, int signatureOffset, int signatureMaxLength, int signContext, int hashContext)
        {
            int num2;
            IntPtr signatureLength = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                processStatus(wrapped_CreateSignature(zero, signatureMaxLength, signatureLength, signContext, hashContext));
                int sequenceLength = Marshal.ReadInt32(signatureLength);
                checkIndices(signature, signatureOffset, sequenceLength);
                getPointer(signature, signatureOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_CreateSignature(zero, signatureMaxLength, signatureLength, signContext, hashContext));
                num2 = Marshal.ReadInt32(signatureLength);
            }
            finally
            {
                Marshal.FreeHGlobal(signatureLength);
                releasePointer(bufferHandle);
            }
            return num2;
        }

        public static int CreateSignatureEx(byte[] signature, int signatureMaxLength, int formatType, int signContext, int hashContext, int extraData) =>
            CreateSignatureEx(signature, 0, signatureMaxLength, formatType, signContext, hashContext, extraData);

        public static int CreateSignatureEx(byte[] signature, int signatureOffset, int signatureMaxLength, int formatType, int signContext, int hashContext, int extraData)
        {
            int num2;
            IntPtr signatureLength = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                processStatus(wrapped_CreateSignatureEx(zero, signatureMaxLength, signatureLength, formatType, signContext, hashContext, extraData));
                int sequenceLength = Marshal.ReadInt32(signatureLength);
                checkIndices(signature, signatureOffset, sequenceLength);
                getPointer(signature, signatureOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_CreateSignatureEx(zero, signatureMaxLength, signatureLength, formatType, signContext, hashContext, extraData));
                num2 = Marshal.ReadInt32(signatureLength);
            }
            finally
            {
                Marshal.FreeHGlobal(signatureLength);
                releasePointer(bufferHandle);
            }
            return num2;
        }

        public static void Decrypt(int cryptContext, byte[] buffer)
        {
            Decrypt(cryptContext, buffer, 0, (buffer == null) ? 0 : buffer.Length);
        }

        public static void Decrypt(int cryptContext, byte[] buffer, int bufferOffset, int length)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(buffer, bufferOffset, length);
                getPointer(buffer, bufferOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_Decrypt(cryptContext, zero, length));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static void DeleteAttribute(int cryptHandle, int attributeType)
        {
            processStatus(wrapped_DeleteAttribute(cryptHandle, attributeType));
        }

        public static void DeleteCertExtension(int certificate, string oid)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(oid);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                processStatus(wrapped_DeleteCertExtension(certificate, zero));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static void DeleteKey(int keyset, int keyIDtype, string keyID)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(keyID);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                processStatus(wrapped_DeleteKey(keyset, keyIDtype, zero));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static void DestroyCert(int certificate)
        {
            processStatus(wrapped_DestroyCert(certificate));
        }

        public static void DestroyContext(int cryptContext)
        {
            processStatus(wrapped_DestroyContext(cryptContext));
        }

        public static void DestroyEnvelope(int envelope)
        {
            processStatus(wrapped_DestroyEnvelope(envelope));
        }

        public static void DestroyObject(int cryptObject)
        {
            processStatus(wrapped_DestroyObject(cryptObject));
        }

        public static void DestroySession(int session)
        {
            processStatus(wrapped_DestroySession(session));
        }

        public static void DeviceClose(int device)
        {
            processStatus(wrapped_DeviceClose(device));
        }

        public static int DeviceCreateContext(int device, int cryptAlgo)
        {
            int num;
            IntPtr cryptContext = Marshal.AllocHGlobal(4);
            try
            {
                processStatus(wrapped_DeviceCreateContext(device, cryptContext, cryptAlgo));
                num = Marshal.ReadInt32(cryptContext);
            }
            finally
            {
                Marshal.FreeHGlobal(cryptContext);
            }
            return num;
        }

        public static int DeviceOpen(int cryptUser, int deviceType, string name)
        {
            int num;
            IntPtr device = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(name);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                processStatus(wrapped_DeviceOpen(device, cryptUser, deviceType, zero));
                num = Marshal.ReadInt32(device);
            }
            finally
            {
                Marshal.FreeHGlobal(device);
                releasePointer(bufferHandle);
            }
            return num;
        }

        public static CRYPT_QUERY_INFO DeviceQueryCapability(int device, int cryptAlgo)
        {
            CRYPT_QUERY_INFO crypt_query_info2;
            IntPtr cryptQueryInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_QUERY_INFO)));
            CRYPT_QUERY_INFO structure = new CRYPT_QUERY_INFO();
            try
            {
                processStatus(wrapped_DeviceQueryCapability(device, cryptAlgo, cryptQueryInfo));
                Marshal.PtrToStructure(cryptQueryInfo, structure);
                crypt_query_info2 = structure;
            }
            finally
            {
                Marshal.FreeHGlobal(cryptQueryInfo);
            }
            return crypt_query_info2;
        }

        public static void Encrypt(int cryptContext, byte[] buffer)
        {
            Encrypt(cryptContext, buffer, 0, (buffer == null) ? 0 : buffer.Length);
        }

        public static void Encrypt(int cryptContext, byte[] buffer, int bufferOffset, int length)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(buffer, bufferOffset, length);
                getPointer(buffer, bufferOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_Encrypt(cryptContext, zero, length));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static void End()
        {
            processStatus(wrapped_End());
        }

        public static int ExportCert(byte[] certObject, int certObjectMaxLength, int certFormatType, int certificate) =>
            ExportCert(certObject, 0, certObjectMaxLength, certFormatType, certificate);

        public static int ExportCert(byte[] certObject, int certObjectOffset, int certObjectMaxLength, int certFormatType, int certificate)
        {
            int num2;
            IntPtr certObjectLength = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                processStatus(wrapped_ExportCert(zero, certObjectMaxLength, certObjectLength, certFormatType, certificate));
                int sequenceLength = Marshal.ReadInt32(certObjectLength);
                checkIndices(certObject, certObjectOffset, sequenceLength);
                getPointer(certObject, certObjectOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_ExportCert(zero, certObjectMaxLength, certObjectLength, certFormatType, certificate));
                num2 = Marshal.ReadInt32(certObjectLength);
            }
            finally
            {
                Marshal.FreeHGlobal(certObjectLength);
                releasePointer(bufferHandle);
            }
            return num2;
        }

        public static int ExportKey(byte[] encryptedKey, int encryptedKeyMaxLength, int exportKey, int sessionKeyContext) =>
            ExportKey(encryptedKey, 0, encryptedKeyMaxLength, exportKey, sessionKeyContext);

        public static int ExportKey(byte[] encryptedKey, int encryptedKeyOffset, int encryptedKeyMaxLength, int exportKey, int sessionKeyContext)
        {
            int num2;
            IntPtr encryptedKeyLength = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                processStatus(wrapped_ExportKey(zero, encryptedKeyMaxLength, encryptedKeyLength, exportKey, sessionKeyContext));
                int sequenceLength = Marshal.ReadInt32(encryptedKeyLength);
                checkIndices(encryptedKey, encryptedKeyOffset, sequenceLength);
                getPointer(encryptedKey, encryptedKeyOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_ExportKey(zero, encryptedKeyMaxLength, encryptedKeyLength, exportKey, sessionKeyContext));
                num2 = Marshal.ReadInt32(encryptedKeyLength);
            }
            finally
            {
                Marshal.FreeHGlobal(encryptedKeyLength);
                releasePointer(bufferHandle);
            }
            return num2;
        }

        public static int ExportKeyEx(byte[] encryptedKey, int encryptedKeyMaxLength, int formatType, int exportKey, int sessionKeyContext) =>
            ExportKeyEx(encryptedKey, 0, encryptedKeyMaxLength, formatType, exportKey, sessionKeyContext);

        public static int ExportKeyEx(byte[] encryptedKey, int encryptedKeyOffset, int encryptedKeyMaxLength, int formatType, int exportKey, int sessionKeyContext)
        {
            int num2;
            IntPtr encryptedKeyLength = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                processStatus(wrapped_ExportKeyEx(zero, encryptedKeyMaxLength, encryptedKeyLength, formatType, exportKey, sessionKeyContext));
                int sequenceLength = Marshal.ReadInt32(encryptedKeyLength);
                checkIndices(encryptedKey, encryptedKeyOffset, sequenceLength);
                getPointer(encryptedKey, encryptedKeyOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_ExportKeyEx(zero, encryptedKeyMaxLength, encryptedKeyLength, formatType, exportKey, sessionKeyContext));
                num2 = Marshal.ReadInt32(encryptedKeyLength);
            }
            finally
            {
                Marshal.FreeHGlobal(encryptedKeyLength);
                releasePointer(bufferHandle);
            }
            return num2;
        }

        public static void FlushData(int envelope)
        {
            processStatus(wrapped_FlushData(envelope));
        }

        public static void GenerateKey(int cryptContext)
        {
            processStatus(wrapped_GenerateKey(cryptContext));
        }

        public static int GetAttribute(int cryptHandle, int attributeType)
        {
            int num;
            IntPtr ptr = Marshal.AllocHGlobal(4);
            try
            {
                processStatus(wrapped_GetAttribute(cryptHandle, attributeType, ptr));
                num = Marshal.ReadInt32(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
            return num;
        }

        public static string GetAttributeString(int cryptHandle, int attributeType)
        {
            byte[] bytes = new byte[GetAttributeString(cryptHandle, attributeType, null)];
            return new UTF8Encoding().GetString(bytes, 0, GetAttributeString(cryptHandle, attributeType, bytes));
        }

        public static int GetAttributeString(int cryptHandle, int attributeType, byte[] value) =>
            GetAttributeString(cryptHandle, attributeType, value, 0);

        public static int GetAttributeString(int cryptHandle, int attributeType, byte[] value, int valueOffset)
        {
            int num2;
            IntPtr valueLength = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                processStatus(wrapped_GetAttributeString(cryptHandle, attributeType, zero, valueLength));
                int sequenceLength = Marshal.ReadInt32(valueLength);
                checkIndices(value, valueOffset, sequenceLength);
                getPointer(value, valueOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_GetAttributeString(cryptHandle, attributeType, zero, valueLength));
                num2 = Marshal.ReadInt32(valueLength);
            }
            finally
            {
                Marshal.FreeHGlobal(valueLength);
                releasePointer(bufferHandle);
            }
            return num2;
        }

        public static int GetCertExtension(int certificate, string oid, byte[] extension, int extensionMaxLength) =>
            GetCertExtension(certificate, oid, extension, 0, extensionMaxLength);

        public static int GetCertExtension(int certificate, string oid, byte[] extension, int extensionOffset, int extensionMaxLength)
        {
            int num2;
            IntPtr extensionLength = Marshal.AllocHGlobal(4);
            IntPtr criticalFlag = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(oid);
            GCHandle handle2 = new GCHandle();
            IntPtr ptr4 = IntPtr.Zero;
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                processStatus(wrapped_GetCertExtension(certificate, zero, criticalFlag, ptr4, extensionMaxLength, extensionLength));
                int sequenceLength = Marshal.ReadInt32(extensionLength);
                checkIndices(extension, extensionOffset, sequenceLength);
                getPointer(extension, extensionOffset, ref handle2, ref ptr4);
                processStatus(wrapped_GetCertExtension(certificate, zero, criticalFlag, ptr4, extensionMaxLength, extensionLength));
                num2 = Marshal.ReadInt32(extensionLength);
            }
            finally
            {
                Marshal.FreeHGlobal(extensionLength);
                releasePointer(handle2);
                releasePointer(bufferHandle);
            }
            return num2;
        }

        public static int GetKey(int keyset, int keyIDtype, string keyID, string password)
        {
            int num;
            IntPtr cryptContext = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(keyID);
            GCHandle handle2 = new GCHandle();
            IntPtr bufferPtr = IntPtr.Zero;
            byte[] buffer = new UTF8Encoding().GetBytes(password);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                getPointer(buffer, 0, ref handle2, ref bufferPtr);
                processStatus(wrapped_GetKey(keyset, cryptContext, keyIDtype, zero, bufferPtr));
                num = Marshal.ReadInt32(cryptContext);
            }
            finally
            {
                Marshal.FreeHGlobal(cryptContext);
                releasePointer(bufferHandle);
                releasePointer(handle2);
            }
            return num;
        }

        private static void getPointer(byte[] buffer, int bufferOffset, ref GCHandle bufferHandle, ref IntPtr bufferPtr)
        {
            if (buffer != null)
            {
                bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                bufferPtr = Marshal.UnsafeAddrOfPinnedArrayElement(buffer, bufferOffset);
            }
        }

        public static int GetPrivateKey(int keyset, int keyIDtype, string keyID, string password)
        {
            int num;
            IntPtr cryptContext = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(keyID);
            GCHandle handle2 = new GCHandle();
            IntPtr bufferPtr = IntPtr.Zero;
            byte[] buffer = new UTF8Encoding().GetBytes(password);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                getPointer(buffer, 0, ref handle2, ref bufferPtr);
                processStatus(wrapped_GetPrivateKey(keyset, cryptContext, keyIDtype, zero, bufferPtr));
                num = Marshal.ReadInt32(cryptContext);
            }
            finally
            {
                Marshal.FreeHGlobal(cryptContext);
                releasePointer(bufferHandle);
                releasePointer(handle2);
            }
            return num;
        }

        public static int GetPublicKey(int keyset, int keyIDtype, string keyID)
        {
            int num;
            IntPtr cryptContext = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(keyID);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                processStatus(wrapped_GetPublicKey(keyset, cryptContext, keyIDtype, zero));
                num = Marshal.ReadInt32(cryptContext);
            }
            finally
            {
                Marshal.FreeHGlobal(cryptContext);
                releasePointer(bufferHandle);
            }
            return num;
        }

        public static int ImportCert(byte[] certObject, int cryptUser) =>
            ImportCert(certObject, 0, (certObject == null) ? 0 : certObject.Length, cryptUser);

        public static int ImportCert(string certObject, int cryptUser) =>
            ImportCert((certObject == null) ? null : new UTF8Encoding().GetBytes(certObject), 0, (certObject == null) ? 0 : new UTF8Encoding().GetByteCount(certObject), cryptUser);

        public static int ImportCert(byte[] certObject, int certObjectOffset, int certObjectLength, int cryptUser)
        {
            int num;
            IntPtr certificate = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(certObject, certObjectOffset, certObjectLength);
                getPointer(certObject, certObjectOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_ImportCert(zero, certObjectLength, cryptUser, certificate));
                num = Marshal.ReadInt32(certificate);
            }
            finally
            {
                Marshal.FreeHGlobal(certificate);
                releasePointer(bufferHandle);
            }
            return num;
        }

        public static void ImportKey(byte[] encryptedKey, int importKey, int sessionKeyContext)
        {
            ImportKey(encryptedKey, 0, (encryptedKey == null) ? 0 : encryptedKey.Length, importKey, sessionKeyContext);
        }

        public static void ImportKey(string encryptedKey, int importKey, int sessionKeyContext)
        {
            ImportKey((encryptedKey == null) ? null : new UTF8Encoding().GetBytes(encryptedKey), 0, (encryptedKey == null) ? 0 : new UTF8Encoding().GetByteCount(encryptedKey), importKey, sessionKeyContext);
        }

        public static void ImportKey(byte[] encryptedKey, int encryptedKeyOffset, int encryptedKeyLength, int importKey, int sessionKeyContext)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(encryptedKey, encryptedKeyOffset, encryptedKeyLength);
                getPointer(encryptedKey, encryptedKeyOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_ImportKey(zero, encryptedKeyLength, importKey, sessionKeyContext));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static int ImportKeyEx(byte[] encryptedKey, int importKey, int sessionKeyContext) =>
            ImportKeyEx(encryptedKey, 0, (encryptedKey == null) ? 0 : encryptedKey.Length, importKey, sessionKeyContext);

        public static int ImportKeyEx(string encryptedKey, int importKey, int sessionKeyContext) =>
            ImportKeyEx((encryptedKey == null) ? null : new UTF8Encoding().GetBytes(encryptedKey), 0, (encryptedKey == null) ? 0 : new UTF8Encoding().GetByteCount(encryptedKey), importKey, sessionKeyContext);

        public static int ImportKeyEx(byte[] encryptedKey, int encryptedKeyOffset, int encryptedKeyLength, int importKey, int sessionKeyContext)
        {
            int num;
            IntPtr returnedContext = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(encryptedKey, encryptedKeyOffset, encryptedKeyLength);
                getPointer(encryptedKey, encryptedKeyOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_ImportKeyEx(zero, encryptedKeyLength, importKey, sessionKeyContext, returnedContext));
                num = Marshal.ReadInt32(returnedContext);
            }
            finally
            {
                Marshal.FreeHGlobal(returnedContext);
                releasePointer(bufferHandle);
            }
            return num;
        }

        public static void Init()
        {
            processStatus(wrapped_Init());
        }

    

        public static void KeysetClose(int keyset)
        {
            processStatus(wrapped_KeysetClose(keyset));
        }

        public static int KeysetOpen(int cryptUser, int keysetType, string name, int options)
        {
            int num;
            IntPtr keyset = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(name);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                processStatus(wrapped_KeysetOpen(keyset, cryptUser, keysetType, zero, options));
                num = Marshal.ReadInt32(keyset);
            }
            finally
            {
                Marshal.FreeHGlobal(keyset);
                releasePointer(bufferHandle);
            }
            return num;
        }

        public static int Login(string name, string password)
        {
            int num;
            IntPtr user = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            byte[] bytes = new UTF8Encoding().GetBytes(name);
            GCHandle handle2 = new GCHandle();
            IntPtr bufferPtr = IntPtr.Zero;
            byte[] buffer = new UTF8Encoding().GetBytes(password);
            try
            {
                getPointer(bytes, 0, ref bufferHandle, ref zero);
                getPointer(buffer, 0, ref handle2, ref bufferPtr);
                processStatus(wrapped_Login(user, zero, bufferPtr));
                num = Marshal.ReadInt32(user);
            }
            finally
            {
                Marshal.FreeHGlobal(user);
                releasePointer(bufferHandle);
                releasePointer(handle2);
            }
            return num;
        }

        public static void Logout(int user)
        {
            processStatus(wrapped_Logout(user));
        }

        public static int PopData(int envelope, byte[] buffer, int length) =>
            PopData(envelope, buffer, 0, length);

        public static int PopData(int envelope, byte[] buffer, int bufferOffset, int length)
        {
            int num3;
            IntPtr ptr = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                int sequenceLength = 0;
                checkIndices(buffer, bufferOffset, sequenceLength);
                getPointer(buffer, bufferOffset, ref bufferHandle, ref zero);
                sequenceLength = Marshal.ReadInt32(ptr);
                processStatus(wrapped_PopData(envelope, zero, length, ptr), sequenceLength);
                num3 = sequenceLength;
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
                releasePointer(bufferHandle);
            }
            return num3;
        }

        private static void processStatus(int status)
        {
            if (status < 0)
            {
                throw new CryptException(status);
            }
        }

        private static void processStatus(int status, int extraInfo)
        {
            if (status < 0)
            {
                throw new CryptException(status, extraInfo);
            }
        }

        public static int PushData(int envelope, byte[] buffer) =>
            PushData(envelope, buffer, 0, (buffer == null) ? 0 : buffer.Length);

        public static int PushData(int envelope, string buffer) =>
            PushData(envelope, (buffer == null) ? null : new UTF8Encoding().GetBytes(buffer), 0, (buffer == null) ? 0 : new UTF8Encoding().GetByteCount(buffer));

        public static int PushData(int envelope, byte[] buffer, int bufferOffset, int length)
        {
            int num3;
            IntPtr ptr = Marshal.AllocHGlobal(4);
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                int extraInfo = 0;
                checkIndices(buffer, bufferOffset, length);
                getPointer(buffer, bufferOffset, ref bufferHandle, ref zero);
                extraInfo = Marshal.ReadInt32(ptr);
                processStatus(wrapped_PushData(envelope, zero, length, ptr), extraInfo);
                num3 = extraInfo;
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
                releasePointer(bufferHandle);
            }
            return num3;
        }

        public static CRYPT_QUERY_INFO QueryCapability(int cryptAlgo)
        {
            CRYPT_QUERY_INFO crypt_query_info2;
            IntPtr cryptQueryInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_QUERY_INFO)));
            CRYPT_QUERY_INFO structure = new CRYPT_QUERY_INFO();
            try
            {
                processStatus(wrapped_QueryCapability(cryptAlgo, cryptQueryInfo));
                Marshal.PtrToStructure(cryptQueryInfo, structure);
                crypt_query_info2 = structure;
            }
            finally
            {
                Marshal.FreeHGlobal(cryptQueryInfo);
            }
            return crypt_query_info2;
        }

        public static CRYPT_OBJECT_INFO QueryObject(byte[] objectData) =>
            QueryObject(objectData, 0, (objectData == null) ? 0 : objectData.Length);

        public static CRYPT_OBJECT_INFO QueryObject(string objectData) =>
            QueryObject((objectData == null) ? null : new UTF8Encoding().GetBytes(objectData), 0, (objectData == null) ? 0 : new UTF8Encoding().GetByteCount(objectData));

        public static CRYPT_OBJECT_INFO QueryObject(byte[] objectData, int objectDataOffset, int objectDataLength)
        {
            CRYPT_OBJECT_INFO crypt_object_info2;
            IntPtr cryptObjectInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_OBJECT_INFO)));
            CRYPT_OBJECT_INFO structure = new CRYPT_OBJECT_INFO();
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(objectData, objectDataOffset, objectDataLength);
                getPointer(objectData, objectDataOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_QueryObject(zero, objectDataLength, cryptObjectInfo));
                Marshal.PtrToStructure(cryptObjectInfo, structure);
                crypt_object_info2 = structure;
            }
            finally
            {
                Marshal.FreeHGlobal(cryptObjectInfo);
                releasePointer(bufferHandle);
            }
            return crypt_object_info2;
        }

        private static void releasePointer(GCHandle bufferHandle)
        {
            if (bufferHandle.IsAllocated)
            {
                bufferHandle.Free();
            }
        }

        public static void SetAttribute(int cryptHandle, int attributeType, int value)
        {
            processStatus(wrapped_SetAttribute(cryptHandle, attributeType, value));
        }

        public static void SetAttributeString(int cryptHandle, int attributeType, byte[] value)
        {
            SetAttributeString(cryptHandle, attributeType, value, 0, (value == null) ? 0 : value.Length);
        }

        public static void SetAttributeString(int cryptHandle, int attributeType, string value)
        {
            SetAttributeString(cryptHandle, attributeType, (value == null) ? null : new UTF8Encoding().GetBytes(value), 0, (value == null) ? 0 : new UTF8Encoding().GetByteCount(value));
        }

        public static void SetAttributeString(int cryptHandle, int attributeType, byte[] value, int valueOffset, int valueLength)
        {
            GCHandle bufferHandle = new GCHandle();
            IntPtr zero = IntPtr.Zero;
            try
            {
                checkIndices(value, valueOffset, valueLength);
                getPointer(value, valueOffset, ref bufferHandle, ref zero);
                processStatus(wrapped_SetAttributeString(cryptHandle, attributeType, zero, valueLength));
            }
            finally
            {
                releasePointer(bufferHandle);
            }
        }

        public static void SignCert(int certificate, int signContext)
        {
            processStatus(wrapped_SignCert(certificate, signContext));
        }

        [DllImport("cl32.dll", EntryPoint = "cryptAddCertExtension")]
        private static extern int wrapped_AddCertExtension(int certificate, IntPtr oid, int criticalFlag, IntPtr extension, int extensionLength);
        [DllImport("cl32.dll", EntryPoint = "cryptAddPrivateKey")]
        private static extern int wrapped_AddPrivateKey(int keyset, int cryptKey, IntPtr password);
        [DllImport("cl32.dll", EntryPoint = "cryptAddPublicKey")]
        private static extern int wrapped_AddPublicKey(int keyset, int certificate);
        [DllImport("cl32.dll", EntryPoint = "cryptAddRandom")]
        private static extern int wrapped_AddRandom(IntPtr randomData, int randomDataLength);
        [DllImport("cl32.dll", EntryPoint = "cryptCAAddItem")]
        private static extern int wrapped_CAAddItem(int keyset, int certificate);
        [DllImport("cl32.dll", EntryPoint = "cryptCACertManagement")]
        private static extern int wrapped_CACertManagement(IntPtr certificate, int action, int keyset, int caKey, int certRequest);
        [DllImport("cl32.dll", EntryPoint = "cryptCADeleteItem")]
        private static extern int wrapped_CADeleteItem(int keyset, int certType, int keyIDtype, IntPtr keyID);
        [DllImport("cl32.dll", EntryPoint = "cryptCAGetItem")]
        private static extern int wrapped_CAGetItem(int keyset, IntPtr certificate, int certType, int keyIDtype, IntPtr keyID);
        [DllImport("cl32.dll", EntryPoint = "cryptCheckCert")]
        private static extern int wrapped_CheckCert(int certificate, int sigCheckKey);
        [DllImport("cl32.dll", EntryPoint = "cryptCheckSignature")]
        private static extern int wrapped_CheckSignature(IntPtr signature, int signatureLength, int sigCheckKey, int hashContext);
        [DllImport("cl32.dll", EntryPoint = "cryptCheckSignatureEx")]
        private static extern int wrapped_CheckSignatureEx(IntPtr signature, int signatureLength, int sigCheckKey, int hashContext, IntPtr extraData);
        [DllImport("cl32.dll", EntryPoint = "cryptCreateCert")]
        private static extern int wrapped_CreateCert(IntPtr certificate, int cryptUser, int certType);
        [DllImport("cl32.dll", EntryPoint = "cryptCreateContext")]
        private static extern int wrapped_CreateContext(IntPtr cryptContext, int cryptUser, int cryptAlgo);
        [DllImport("cl32.dll", EntryPoint = "cryptCreateEnvelope")]
        private static extern int wrapped_CreateEnvelope(IntPtr envelope, int cryptUser, int formatType);
        [DllImport("cl32.dll", EntryPoint = "cryptCreateSession")]
        private static extern int wrapped_CreateSession(IntPtr session, int cryptUser, int formatType);
        [DllImport("cl32.dll", EntryPoint = "cryptCreateSignature")]
        private static extern int wrapped_CreateSignature(IntPtr signature, int signatureMaxLength, IntPtr signatureLength, int signContext, int hashContext);
        [DllImport("cl32.dll", EntryPoint = "cryptCreateSignatureEx")]
        private static extern int wrapped_CreateSignatureEx(IntPtr signature, int signatureMaxLength, IntPtr signatureLength, int formatType, int signContext, int hashContext, int extraData);
        [DllImport("cl32.dll", EntryPoint = "cryptDecrypt")]
        private static extern int wrapped_Decrypt(int cryptContext, IntPtr buffer, int length);
        [DllImport("cl32.dll", EntryPoint = "cryptDeleteAttribute")]
        private static extern int wrapped_DeleteAttribute(int cryptHandle, int attributeType);
        [DllImport("cl32.dll", EntryPoint = "cryptDeleteCertExtension")]
        private static extern int wrapped_DeleteCertExtension(int certificate, IntPtr oid);
        [DllImport("cl32.dll", EntryPoint = "cryptDeleteKey")]
        private static extern int wrapped_DeleteKey(int keyset, int keyIDtype, IntPtr keyID);
        [DllImport("cl32.dll", EntryPoint = "cryptDestroyCert")]
        private static extern int wrapped_DestroyCert(int certificate);
        [DllImport("cl32.dll", EntryPoint = "cryptDestroyContext")]
        private static extern int wrapped_DestroyContext(int cryptContext);
        [DllImport("cl32.dll", EntryPoint = "cryptDestroyEnvelope")]
        private static extern int wrapped_DestroyEnvelope(int envelope);
        [DllImport("cl32.dll", EntryPoint = "cryptDestroyObject")]
        private static extern int wrapped_DestroyObject(int cryptObject);
        [DllImport("cl32.dll", EntryPoint = "cryptDestroySession")]
        private static extern int wrapped_DestroySession(int session);
        [DllImport("cl32.dll", EntryPoint = "cryptDeviceClose")]
        private static extern int wrapped_DeviceClose(int device);
        [DllImport("cl32.dll", EntryPoint = "cryptDeviceCreateContext")]
        private static extern int wrapped_DeviceCreateContext(int device, IntPtr cryptContext, int cryptAlgo);
        [DllImport("cl32.dll", EntryPoint = "cryptDeviceOpen")]
        private static extern int wrapped_DeviceOpen(IntPtr device, int cryptUser, int deviceType, IntPtr name);
        [DllImport("cl32.dll", EntryPoint = "cryptDeviceQueryCapability")]
        private static extern int wrapped_DeviceQueryCapability(int device, int cryptAlgo, IntPtr cryptQueryInfo);
        [DllImport("cl32.dll", EntryPoint = "cryptEncrypt")]
        private static extern int wrapped_Encrypt(int cryptContext, IntPtr buffer, int length);
        [DllImport("cl32.dll", EntryPoint = "cryptEnd")]
        private static extern int wrapped_End();
        [DllImport("cl32.dll", EntryPoint = "cryptExportCert")]
        private static extern int wrapped_ExportCert(IntPtr certObject, int certObjectMaxLength, IntPtr certObjectLength, int certFormatType, int certificate);
        [DllImport("cl32.dll", EntryPoint = "cryptExportKey")]
        private static extern int wrapped_ExportKey(IntPtr encryptedKey, int encryptedKeyMaxLength, IntPtr encryptedKeyLength, int exportKey, int sessionKeyContext);
        [DllImport("cl32.dll", EntryPoint = "cryptExportKeyEx")]
        private static extern int wrapped_ExportKeyEx(IntPtr encryptedKey, int encryptedKeyMaxLength, IntPtr encryptedKeyLength, int formatType, int exportKey, int sessionKeyContext);
        [DllImport("cl32.dll", EntryPoint = "cryptFlushData")]
        private static extern int wrapped_FlushData(int envelope);
        [DllImport("cl32.dll", EntryPoint = "cryptGenerateKey")]
        private static extern int wrapped_GenerateKey(int cryptContext);
        [DllImport("cl32.dll", EntryPoint = "cryptGetAttribute")]
        private static extern int wrapped_GetAttribute(int cryptHandle, int attributeType, IntPtr value);
        [DllImport("cl32.dll", EntryPoint = "cryptGetAttributeString")]
        private static extern int wrapped_GetAttributeString(int cryptHandle, int attributeType, IntPtr value, IntPtr valueLength);
        [DllImport("cl32.dll", EntryPoint = "cryptGetCertExtension")]
        private static extern int wrapped_GetCertExtension(int certificate, IntPtr oid, IntPtr criticalFlag, IntPtr extension, int extensionMaxLength, IntPtr extensionLength);
        [DllImport("cl32.dll", EntryPoint = "cryptGetKey")]
        private static extern int wrapped_GetKey(int keyset, IntPtr cryptContext, int keyIDtype, IntPtr keyID, IntPtr password);
        [DllImport("cl32.dll", EntryPoint = "cryptGetPrivateKey")]
        private static extern int wrapped_GetPrivateKey(int keyset, IntPtr cryptContext, int keyIDtype, IntPtr keyID, IntPtr password);
        [DllImport("cl32.dll", EntryPoint = "cryptGetPublicKey")]
        private static extern int wrapped_GetPublicKey(int keyset, IntPtr cryptContext, int keyIDtype, IntPtr keyID);
        [DllImport("cl32.dll", EntryPoint = "cryptImportCert")]
        private static extern int wrapped_ImportCert(IntPtr certObject, int certObjectLength, int cryptUser, IntPtr certificate);
        [DllImport("cl32.dll", EntryPoint = "cryptImportKey")]
        private static extern int wrapped_ImportKey(IntPtr encryptedKey, int encryptedKeyLength, int importKey, int sessionKeyContext);
        [DllImport("cl32.dll", EntryPoint = "cryptImportKeyEx")]
        private static extern int wrapped_ImportKeyEx(IntPtr encryptedKey, int encryptedKeyLength, int importKey, int sessionKeyContext, IntPtr returnedContext);
        [DllImport("cl32.dll", EntryPoint = "cryptInit")]
        private static extern int wrapped_Init();
        [DllImport("cl32.dll", EntryPoint = "cryptKeysetClose")]
        private static extern int wrapped_KeysetClose(int keyset);
        [DllImport("cl32.dll", EntryPoint = "cryptKeysetOpen")]
        private static extern int wrapped_KeysetOpen(IntPtr keyset, int cryptUser, int keysetType, IntPtr name, int options);
        [DllImport("cl32.dll", EntryPoint = "cryptLogin")]
        private static extern int wrapped_Login(IntPtr user, IntPtr name, IntPtr password);
        [DllImport("cl32.dll", EntryPoint = "cryptLogout")]
        private static extern int wrapped_Logout(int user);
        [DllImport("cl32.dll", EntryPoint = "cryptPopData")]
        private static extern int wrapped_PopData(int envelope, IntPtr buffer, int length, IntPtr bytesCopied);
        [DllImport("cl32.dll", EntryPoint = "cryptPushData")]
        private static extern int wrapped_PushData(int envelope, IntPtr buffer, int length, IntPtr bytesCopied);
        [DllImport("cl32.dll", EntryPoint = "cryptQueryCapability")]
        private static extern int wrapped_QueryCapability(int cryptAlgo, IntPtr cryptQueryInfo);
        [DllImport("cl32.dll", EntryPoint = "cryptQueryObject")]
        private static extern int wrapped_QueryObject(IntPtr objectData, int objectDataLength, IntPtr cryptObjectInfo);
        [DllImport("cl32.dll", EntryPoint = "cryptSetAttribute")]
        private static extern int wrapped_SetAttribute(int cryptHandle, int attributeType, int value);
        [DllImport("cl32.dll", EntryPoint = "cryptSetAttributeString")]
        private static extern int wrapped_SetAttributeString(int cryptHandle, int attributeType, IntPtr value, int valueLength);
        [DllImport("cl32.dll", EntryPoint = "cryptSignCert")]
        private static extern int wrapped_SignCert(int certificate, int signContext);

        internal static void CreateContext(int cryptContext, object cRYPT_ALGO_RSA)
        {
            throw new NotImplementedException();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class CRYPT_QUERY_INFO
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 0x40)]
        public string algoName;
        public int blockSize;
        public int minKeySize;
        public int keySize;
        public int maxKeySize;
        public CRYPT_QUERY_INFO()
        {
        }

        public CRYPT_QUERY_INFO(string newAlgoName, int newBlockSize, int newMinKeySize, int newKeySize, int newMaxKeySize)
        {
            this.algoName = newAlgoName;
            this.blockSize = newBlockSize;
            this.minKeySize = newMinKeySize;
            this.keySize = newKeySize;
            this.maxKeySize = newMaxKeySize;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public class CRYPT_OBJECT_INFO
    {
        public int objectType;
        public int cryptAlgo;
        public int cryptMode;
        public int hashAlgo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public byte[] salt;
        public int saltSize;
        public CRYPT_OBJECT_INFO()
        {
            this.salt = new byte[0x40];
            this.saltSize = 0x40;
        }

        public CRYPT_OBJECT_INFO(int newObjectType, int newCryptAlgo, int newCryptMode, int newHashAlgo, byte[] newSalt)
        {
            this.objectType = newObjectType;
            this.cryptAlgo = newCryptAlgo;
            this.cryptMode = newCryptMode;
            this.hashAlgo = newHashAlgo;
        }
    }


    [StructLayout(LayoutKind.Sequential)]
    public class CRYPT_PKCINFO_RSA
    {
        public int isPublicKey;
        public IntPtr n;
        public int nLen;
        public IntPtr e;
        public int eLen;
        public IntPtr d;
        public int dLen;
        public IntPtr p;
        public int pLen;
        public IntPtr q;
        public int qLen;
        public IntPtr u;
        public int uLen;
        public IntPtr e1;
        public int e1Len;
        public IntPtr e2;
        public int e2Len;
    }



    public class CryptException : ApplicationException
    {
        // Methods
        public CryptException(int status) : base(convertMessage(status))
        {
            this.Data.Add("Status", status);
        }

        public CryptException(int status, int extra) : base(convertMessage(status))
        {
            this.Data.Add("Status", status);
            this.Data.Add("ExtraInfo", extra);
        }

        private static string convertMessage(int status)
        {
            string str = Convert.ToString(status) + ": ";
            switch (status)
            {
                case -50:
                    return (str + "Need resource to proceed");

                case -44:
                    return (str + "Item already present in object");

                case -43:
                    return (str + "Requested item not found in object");

                case -42:
                    return (str + "Cannot write item to object");

                case -41:
                    return (str + "Cannot read item from object");

                case -40:
                    return (str + "Cannot open object");

                case -33:
                    return (str + "Signature/integrity check failed");

                case -32:
                    return (str + "Bad/unrecognised data format");

                case -31:
                    return (str + "Not enough data available");

                case -30:
                    return (str + "Resources/space exhausted");

                case -27:
                    return (str + "Resource destroyed by extnl.event");

                case -26:
                    return (str + "Invalid/inconsistent information");

                case -25:
                    return (str + "Operation timed out before completion");

                case -24:
                    return (str + "Operation complete/can't continue");

                case -23:
                    return (str + "Operation incomplete/still in progress");

                case -22:
                    return (str + "Incorrect key used to decrypt data");

                case -21:
                    return (str + "No permiss.to perform this operation");

                case -20:
                    return (str + "This type of opn.not available");

                case -16:
                    return (str + "Internal consistency check failed");

                case -15:
                    return (str + "Operation failed");

                case -14:
                    return (str + "No reliable random data available");

                case -13:
                    return (str + "Opn.not avail.at requested sec.level");

                case -12:
                    return (str + "Data has already been init'd");

                case -11:
                    return (str + "Data has not been initialised");

                case -10:
                    return (str + "Out of memory");

                case -7:
                    return (str + "Bad argument, parameter 7");

                case -6:
                    return (str + "Bad argument, parameter 6");

                case -5:
                    return (str + "Bad argument, parameter 5");

                case -4:
                    return (str + "Bad argument, parameter 4");

                case -3:
                    return (str + "Bad argument, parameter 3");

                case -2:
                    return (str + "Bad argument, parameter 2");

                case -1:
                    return (str + "Bad argument, parameter 1");
            }
            return (str + "Unknown Exception ?!?!");
        }

        // Properties
        public int Status =>
            (int)this.Data["Status"];

        public int ExtraInfo =>
            (int)this.Data["ExtraInfo"];
    }










}
