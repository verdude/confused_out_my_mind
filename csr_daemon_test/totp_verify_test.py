import socket
import ssl
import sys

EMAIL_TOTP_LENGTH = 6
PHONE_TOTP_LENGTH = 8
test_crt = """-----BEGIN CERTIFICATE REQUEST-----
MIIDMzCCAhsCAQAwfDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxDjAMBgNV
BAcMBVByb3ZvMRQwEgYDVQQKDAtVUyBDaXRpemVuczEWMBQGA1UEAwwNVGFubmVy
IFBlcmR1ZTEgMB4GCSqGSIb3DQEJARYRdGFubmVyQHRhbm5lci5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBitlwHJNS/ns3WPtz4MponRFbPP1U
gZTV7lPbTlC3zTzHNV/q5LIsY7m49f1cpJlikAbkiqXSIbfu674S83XNNutT60aV
zX0Suj4BJQx8qIBiwLhAsM9JGxG/8B/Nxeup0ZJ0omijPnIHNYJJZwrSHF3h95vm
30qUKenxmmWRqWqNmOPl9w9dxHHgQRnsYuA8ErBN355wT0W7IfTex4X3irDe+pPY
66p2+1R9oYNxns41OG5FHJ6gc3IbBLG9UB7xqykw8EoPM6lRRVO5cp9Oy7NA8YiC
H4y9O197v90nocVSdzdX+z4gpxnsmR1VVGIdTJGOBfqWImwsQOd/xsNbAgMBAAGg
cjBwBgkqhkiG9w0BCQ4xYzBhMB0GA1UdDgQWBBSuhUW0yYXwEEDfawCrQYpA7y7p
+jAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDAoBglghkgBhvhCAQ0EGxYZU1NBIEdl
bmVyYXRlZCBDZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQsFAAOCAQEAD2CeUUWDUKK4
LKE2wlaw6IG4CuWh8ZGUBv7onx3Pkgk3Pjv9Y7Ak9CDnfgEQ4duc3UpPtFl+B04E
dQL0W+ls3HIS0q6DREOoj99UCNWtRtCRhtrC/089b+ub4BmJsrOGcegNHb2KG0Pp
rWoUzKxbgu8uueX2R4PfeAfrw87jjDz4GpJIEmNDk9E4eI79c4AhBIl6bP2tqh9h
ttJE8TJ+YmG060j80pzZxdT/4w4Nh5SY8E8uDEftFb6hvGTmjg3JlZLgAiMKRVkJ
S0wJKPX1Rt+Rpuz3aBn0mv/eOHPeVGjtg5zC4eVjibi8CD2f60ROfVejQPbQ5cAZ
SMN9ZQ9TRA==
-----END CERTIFICATE REQUEST-----"""

def ssl_request(packet, host="127.0.0.1", port="8040"):
    # SET VARIABLES
    reply = ""
    HOST, PORT = '127.0.0.1', 8040

    # CREATE SOCKET
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    # WRAP SOCKET
    wrappedSocket = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS")

    # CONNECT AND PRINT REPLY
    wrappedSocket.connect((HOST, PORT))
    wrappedSocket.send(packet)
    reply = wrappedSocket.recv(1280)

    # CLOSE SOCKET CONNECTION
    wrappedSocket.close()
    return reply

def parse_totp_resp(r):
    if len(r) == 0:
        print("Error: totp reponse length is zero")
        sys.exit(1)
    email_code_len = ord(r[0])
    email_code = r[1:email_code_len+1]
    phone_code_len = ord(r[email_code_len+1])
    phone_code = r[email_code_len+2:email_code_len+2+phone_code_len+1]
    return (email_code, phone_code)

if __name__ == "__main__":
    # request totps
    phone = "+18014224000"
    phone_length = len(phone)
    email = "me@pm.me"
    email_length = len(email)
    if email_length > 127 or phone_length > 127:
        print("email and phone strings must be less than 127 chars long.")
        sys.exit(1)
    else:
        totp_request = "0"+chr(phone_length)+phone+chr(email_length)+email
        totp_response = ssl_request(totp_request)
        email_code, phone_code = parse_totp_resp(totp_response)

    # verify totps we recieved
    email_totp = raw_input("Enter the email totp:")
    phone_totp = raw_input("Enter the phone totp:")

    if len(email_totp) != EMAIL_TOTP_LENGTH:
        print("invalid length for email totp: %s" % str(len(email_totp)))
        sys.exit(1)
    if len(phone_totp) != PHONE_TOTP_LENGTH:
        print("invalid length for phone totp: %s" % str(len(phone_totp)))
        sys.exit(1)

    validate_totp_request = "1"+chr(len(email_code))+email_code+email_totp+chr(len(phone_code))+phone_code+phone_totp+test_crt
    validate_totp_response = ssl_request(validate_totp_request)
    print(validate_totp_response)

