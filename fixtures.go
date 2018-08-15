package keyremix

// openssl genrsa -out rsa-pkcs1.pem 1024
var rsaPkcs1Pem = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQC9iLFZYoYVNVBPl32eTXMTqDYx+R9NfbewxxUxF8EMvnA7KJ1h
GkQ/jSH5ZzNIIrsJdYyqYUA2ROAFmkJe5ihK76nC1XQd0cRzkWq1W5SX4kjm6ZDp
wG36KIi+Hicec70MwS+DGF/hthsx3pzcJ7dOHbhEXdKOByMa2Ltg/iaLewIDAQAB
AoGAJRuBFW37sGVKvvp65qZlNGEHk0sh/MrzTtH7bSwoaLVURdDS1zMMT6DzGOBC
ownhsp1oF+eIadecQJyOCARpuMPi/PNvknqqrCwQNdgtvcpHgfgI+UJKLOSVQ0f7
5ax8mZkGDoJkWFtpEo0hziTvpqe+HxvSK9997K5QZrVUtJECQQDhUfvl9rPsgRHM
ppKJeCDohhdlVoZA5Dn57PeOs+LCtNp7DHDZHiXiARaeRcQxR23cmP24iN0Nhr9V
HVCmFIj5AkEA11dNLpERWGGhwkjWI4CaVGAlBMIIxcya6solYsE7KkXdhtjhW0WW
4gUJyh6QorQy3c6iXVtBQJpWwshmntSpEwJBAM0fI6DwfE+cGKYkJlb7g4nrOLVK
laHRo24A6kWBQbhbiGJoqvsdVQNwVjTz8m2iR0OCC8jI3+SGfPxxWZA4NZECQQDQ
dRCgLYqO9iQzAXNadtnvKAtt6a+4WvL0qq86RDhUGcHzEexGAL2pGpt5b9Ev0CUV
lzySBw7JzR6D/J9qzg7FAkEAnTJkecYpnXKyEecyfAex8cN/LYQ/vKJKLy0/2/2A
lDed1vlMuAUck3//9Wkxrpk4v+F5Nl7GWLorV9wsbiYCpQ==
-----END RSA PRIVATE KEY-----`

// rsaPkcs1Pem, converted to bytes
var rsaPkcs1Der = []byte{
	48, 130, 2, 94, 2, 1, 0, 2, 129, 129, 0, 189, 136, 177, 89, 98, 134, 21, 53,
	80, 79, 151, 125, 158, 77, 115, 19, 168, 54, 49, 249, 31, 77, 125, 183, 176,
	199, 21, 49, 23, 193, 12, 190, 112, 59, 40, 157, 97, 26, 68, 63, 141, 33, 249,
	103, 51, 72, 34, 187, 9, 117, 140, 170, 97, 64, 54, 68, 224, 5, 154, 66, 94,
	230, 40, 74, 239, 169, 194, 213, 116, 29, 209, 196, 115, 145, 106, 181, 91,
	148, 151, 226, 72, 230, 233, 144, 233, 192, 109, 250, 40, 136, 190, 30,
	39, 30, 115, 189, 12, 193, 47, 131, 24, 95, 225, 182, 27, 49, 222, 156,
	220, 39, 183, 78, 29, 184, 68, 93, 210, 142, 7, 35, 26, 216, 187, 96,
	254, 38, 139, 123, 2, 3, 1, 0, 1, 2, 129, 128, 37, 27, 129, 21, 109, 251,
	176, 101, 74, 190, 250, 122, 230, 166, 101, 52, 97, 7, 147, 75, 33, 252,
	202, 243, 78, 209, 251, 109, 44, 40, 104, 181, 84, 69, 208, 210, 215, 51,
	12, 79, 160, 243, 24, 224, 66, 163, 9, 225, 178, 157, 104, 23, 231, 136,
	105, 215, 156, 64, 156, 142, 8, 4, 105, 184, 195, 226, 252, 243, 111, 146,
	122, 170, 172, 44, 16, 53, 216, 45, 189, 202, 71, 129, 248, 8, 249, 66, 74,
	44, 228, 149, 67, 71, 251, 229, 172, 124, 153, 153, 6, 14, 130, 100, 88, 91,
	105, 18, 141, 33, 206, 36, 239, 166, 167, 190, 31, 27, 210, 43, 223, 125,
	236, 174, 80, 102, 181, 84, 180, 145, 2, 65, 0, 225, 81, 251, 229, 246,
	179, 236, 129, 17, 204, 166, 146, 137, 120, 32, 232, 134, 23, 101, 86,
	134, 64, 228, 57, 249, 236, 247, 142, 179, 226, 194, 180, 218, 123, 12,
	112, 217, 30, 37, 226, 1, 22, 158, 69, 196, 49, 71, 109, 220, 152, 253,
	184, 136, 221, 13, 134, 191, 85, 29, 80, 166, 20, 136, 249, 2, 65, 0, 215,
	87, 77, 46, 145, 17, 88, 97, 161, 194, 72, 214, 35, 128, 154, 84, 96, 37,
	4, 194, 8, 197, 204, 154, 234, 202, 37, 98, 193, 59, 42, 69, 221, 134, 216,
	225, 91, 69, 150, 226, 5, 9, 202, 30, 144, 162, 180, 50, 221, 206, 162, 93,
	91, 65, 64, 154, 86, 194, 200, 102, 158, 212, 169, 19, 2, 65, 0, 205, 31, 35,
	160, 240, 124, 79, 156, 24, 166, 36, 38, 86, 251, 131, 137, 235, 56, 181,
	74, 149, 161, 209, 163, 110, 0, 234, 69, 129, 65, 184, 91, 136, 98, 104,
	170, 251, 29, 85, 3, 112, 86, 52, 243, 242, 109, 162, 71, 67, 130, 11, 200,
	200, 223, 228, 134, 124, 252, 113, 89, 144, 56, 53, 145, 2, 65, 0, 208, 117,
	16, 160, 45, 138, 142, 246, 36, 51, 1, 115, 90, 118, 217, 239, 40, 11,
	109, 233, 175, 184, 90, 242, 244, 170, 175, 58, 68, 56, 84, 25, 193,
	243, 17, 236, 70, 0, 189, 169, 26, 155, 121, 111, 209, 47, 208, 37,
	21, 151, 60, 146, 7, 14, 201, 205, 30, 131, 252, 159, 106, 206, 14, 197,
	2, 65, 0, 157, 50, 100, 121, 198, 41, 157, 114, 178, 17, 231, 50, 124, 7,
	177, 241, 195, 127, 45, 132, 63, 188, 162, 74, 47, 45, 63, 219, 253, 128, 148,
	55, 157, 214, 249, 76, 184, 5, 28, 147, 127, 255, 245, 105, 49, 174, 153, 56,
	191, 225, 121, 54, 94, 198, 88, 186, 43, 87, 220, 44, 110, 38, 2, 165,
}

// openssl genpkey -outform PEM -out rsa-pkcs8.pem -algorithm RSA -pkeyopt rsa_keygen_bits:1024
var rsaPkcs8Pem = `-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAJ+n3bby3zTnCYbn
0ppd6Nd5N3pZ+Aj4aShYoHpBu1N9//FKrsyIp/jKVHMiwlY7KX9sbJLgistmgSi/
CqLG7I7WgkYpPOiPCtgl3ZdnlextbR5vQUEqjy/LXFFbNbk994W+T7+BbOO4rMl2
9yYR6KGjGM9zTRTHmYaZxCgyufXfAgMBAAECgYEAmpiN1G1xPWTKkNtBz0BICv3R
fqRHzUfda7gGDNxBbCOCBj/u6xcYr4wcIjDyRVWcZUq0B7VuMG7densi7WP6Av6k
erezXawpymCu/aYeLuyhcsNdG43THqOC/YL15ep/jIOrJQcnLq/TPNcAZpJsKjra
Pxo2p+UV/PY0EOB+8iECQQDKk86U7hSMBWjdw+JmjfJFvP+A3w8vP+AV/5Qw3isO
dHQgf5/FnhTmROYSZRPiX+FUETERDtyKSxo02zGW5sLFAkEAycJgrnCo/qaHGtEe
A3wKT+XTCiNl0Lc57h9mu3kREHXK8Xr0XdR/HQL4WDzRQjFSquQUOWU2ViHc/c/g
FJKQUwJAbmGHiQMJUxqHf38C2Bq0TmejWRcx8O7/LT1sBAyqrV+q/yJLbqSqgqY8
Lv3AjfLslqAfekn8xaYSi4Z8SNtIeQJBAJwLurswZ4SNR/F1y8DmLxOcrZ0pw5Wq
ISQLJWnaOViBwnUCo/3uXGIT6gBVCYQooceKoBnELkJv7nxgSu+ebAECQQCsLdP6
t0+NftrU/L7m2tfPu2n79TOFHgWpDzQD4Xs+ntyHuDObt6a/1EUbsUXQ89Us5n0J
ysrwY6rW6UXSWSsh
-----END PRIVATE KEY-----
`

// openssl pkey -inform PEM -in rsa-pkcs8.pem -pubout -out rsa-pkcs8-pub.pem
var rsaPkcs8Pub = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCfp9228t805wmG59KaXejXeTd6
WfgI+GkoWKB6QbtTff/xSq7MiKf4ylRzIsJWOyl/bGyS4IrLZoEovwqixuyO1oJG
KTzojwrYJd2XZ5XsbW0eb0FBKo8vy1xRWzW5PfeFvk+/gWzjuKzJdvcmEeihoxjP
c00Ux5mGmcQoMrn13wIDAQAB
-----END PUBLIC KEY-----
`

var rsaPkcs8Der = []byte{
	48, 130, 2, 120, 2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1,
	5, 0, 4, 130, 2, 98, 48, 130, 2, 94, 2, 1, 0, 2, 129, 129, 0, 159, 167, 221,
	182, 242, 223, 52, 231, 9, 134, 231, 210, 154, 93, 232, 215, 121, 55, 122,
	89, 248, 8, 248, 105, 40, 88, 160, 122, 65, 187, 83, 125, 255, 241, 74,
	174, 204, 136, 167, 248, 202, 84, 115, 34, 194, 86, 59, 41, 127, 108,
	108, 146, 224, 138, 203, 102, 129, 40, 191, 10, 162, 198, 236, 142, 214,
	130, 70, 41, 60, 232, 143, 10, 216, 37, 221, 151, 103, 149, 236, 109,
	109, 30, 111, 65, 65, 42, 143, 47, 203, 92, 81, 91, 53, 185, 61, 247,
	133, 190, 79, 191, 129, 108, 227, 184, 172, 201, 118, 247, 38, 17, 232,
	161, 163, 24, 207, 115, 77, 20, 199, 153, 134, 153, 196, 40, 50, 185,
	245, 223, 2, 3, 1, 0, 1, 2, 129, 129, 0, 154, 152, 141, 212, 109, 113,
	61, 100, 202, 144, 219, 65, 207, 64, 72, 10, 253, 209, 126, 164, 71, 205,
	71, 221, 107, 184, 6, 12, 220, 65, 108, 35, 130, 6, 63, 238, 235, 23, 24,
	175, 140, 28, 34, 48, 242, 69, 85, 156, 101, 74, 180, 7, 181, 110, 48,
	110, 221, 122, 123, 34, 237, 99, 250, 2, 254, 164, 122, 183, 179, 93,
	172, 41, 202, 96, 174, 253, 166, 30, 46, 236, 161, 114, 195, 93, 27,
	141, 211, 30, 163, 130, 253, 130, 245, 229, 234, 127, 140, 131, 171,
	37, 7, 39, 46, 175, 211, 60, 215, 0, 102, 146, 108, 42, 58, 218, 63, 26, 54,
	167, 229, 21, 252, 246, 52, 16, 224, 126, 242, 33, 2, 65, 0, 202, 147, 206,
	148, 238, 20, 140, 5, 104, 221, 195, 226, 102, 141, 242, 69, 188, 255, 128,
	223, 15, 47, 63, 224, 21, 255, 148, 48, 222, 43, 14, 116, 116, 32, 127,
	159, 197, 158, 20, 230, 68, 230, 18, 101, 19, 226, 95, 225, 84, 17, 49,
	17, 14, 220, 138, 75, 26, 52, 219, 49, 150, 230, 194, 197, 2, 65, 0,
	201, 194, 96, 174, 112, 168, 254, 166, 135, 26, 209, 30, 3, 124, 10, 79,
	229, 211, 10, 35, 101, 208, 183, 57, 238, 31, 102, 187, 121, 17, 16,
	117, 202, 241, 122, 244, 93, 212, 127, 29, 2, 248, 88, 60, 209, 66,
	49, 82, 170, 228, 20, 57, 101, 54, 86, 33, 220, 253, 207, 224, 20,
	146, 144, 83, 2, 64, 110, 97, 135, 137, 3, 9, 83, 26, 135, 127, 127, 2,
	216, 26, 180, 78, 103, 163, 89, 23, 49, 240, 238, 255, 45, 61, 108, 4, 12, 170,
	173, 95, 170, 255, 34, 75, 110, 164, 170, 130, 166, 60, 46, 253, 192, 141, 242,
	236, 150, 160, 31, 122, 73, 252, 197, 166, 18, 139, 134, 124, 72, 219, 72,
	121, 2, 65, 0, 156, 11, 186, 187, 48, 103, 132, 141, 71, 241, 117, 203,
	192, 230, 47, 19, 156, 173, 157, 41, 195, 149, 170, 33, 36, 11, 37, 105,
	218, 57, 88, 129, 194, 117, 2, 163, 253, 238, 92, 98, 19, 234, 0, 85, 9,
	132, 40, 161, 199, 138, 160, 25, 196, 46, 66, 111, 238, 124, 96, 74, 239,
	158, 108, 1, 2, 65, 0, 172, 45, 211, 250, 183, 79, 141, 126, 218, 212, 252,
	190, 230, 218, 215, 207, 187, 105, 251, 245, 51, 133, 30, 5, 169, 15, 52,
	3, 225, 123, 62, 158, 220, 135, 184, 51, 155, 183, 166, 191, 212, 69, 27,
	177, 69, 208, 243, 213, 44, 230, 125, 9, 202, 202, 240, 99, 170, 214,
	233, 69, 210, 89, 43, 33,
}

// openssl genpkey -outform PEM -out ecopenssl genpkey -outform PEM -out ecdsa-pkcs8.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
var ecdsaPkcs8Pem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg80iHwtQcehdlbQzG
BfFUTILogLwTyIGjRkjQZZBA7jKhRANCAAQOgTCFaTxHKvLVbQF0Cp1Fpdk7U8Am
l9BURNz+W7g1zNJ9WYrL5dm1+7Uv1VX7OHm5ou7J6NR2rJymDMPR/9lW
-----END PRIVATE KEY-----`

// RFC7517 A.1
var ecpuba1 = `{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"enc",
          "kid":"1"},

         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }`

// RFC7157 A.2
var ecpriva2 = `{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
          "use":"enc",
          "kid":"1"},

         {"kty":"RSA",
          "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
          "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
          "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
          "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
          "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
          "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }
`

// RFC7157 A.3
var octa3 = `  {"keys":
       [
         {"kty":"oct",
          "alg":"A128KW",
          "k":"GawgguFyGrWKav7AX4VKUg"},

         {"kty":"oct",
          "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75
     aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
          "kid":"HMAC key used in JWS spec Appendix A.1 example"}
       ]
     }`
