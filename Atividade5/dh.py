# -*- coding: utf-8 -*-

"""
  -> author: Juan Cardoso da Silva - 171257138
  -> author: Guilherme de Aguiar Pacianotto - 181251019
"""

import math
from random import randint

# checagem se os números são primos.
def is_prime(number):
  return all(number % i != 0 for i in range(2, int(math.sqrt(number)) + 1))

# geração de dois números primos grandes
def gen_prime_numbers():
  while(True):
    p = int(input("Digite o primeiro número primo grande\n>:"))
    q = int(input("Digite o primeiro número primo grande\n>:"))
    if(p * q < 400):
      print("Os números pequenos")
    elif(p == q): print("Os números são iguais")
    elif(is_prime(p) and is_prime(q)): break
    else: print("Não são números primos")
  return [p, q]

class DiffieHellman:
  def __init__(self, p, alpha, secret) -> None:
    self.p = p            # Valor p
    self.alpha = alpha    # Valor Alpha
    self.secret = secret  # Secret único de cada cliente, não deve ser compartilhado
    self.x = 0            # Valor x calculado na geração da chave pública.
    self.incoming_x = 0   # Valor que é enviado para fazer o calculo da chave privada.
    self.key = 0          # Valor da chave.
    self.state = False
    self.str_dict = {'a': "101", 'b': "102", 'c': "103", 'd': "104", 'e': "105", 'f': "106", 'g': "107", 'h': "108", 
      'i': "109", 'j': "110", 'k': "111", 'l': "112", 'm': "113", 'n': "114", 'o': "115", 'p': "116", 
      'q': "117", 'r': "118", 's': "119", 't': "120", 'u': "121", 'v': "122", 'w': "123", 'x': "124", 
      'y': "125", 'z': "126", " ": "127", 'A': "201", 'B': "202", 'C': "203", 'D': "204", 'E': "205", 
      'F': "206", 'G': "207", 'H': "208", 'I': "209", 'J': "210", 'K': "211", 'L': "212", 'M': "213", 
      'N': "214", 'O': "215", 'P': "216", 'Q': "217", 'R': "218", 'S': "219", 'T': "220", 'U': "221", 
      'V': "222", 'W': "223", 'X': "224", 'Y': "225", 'Z': "226", ",": "301", ".": "302", '[':"303", ']':"304"
    } # dicionário de strings para gerar a mensagem criptografada.
    

  # Calcular o X
  def calc_x(self):
    self.x = int(pow(self.alpha, self.secret, self.p))
  
  def encrypt_with_key(self, message, key):
    string_as_num = "".join((self.str_dict[message[n]] for n in range(0,len(message))))
    return int(string_as_num) * key
  
  def decrypt_with_key(self, encrypted_message, key):
    message_as_numbers = str(int(encrypted_message // key))
    index = 0
    end_index = 3
    decrypted_message = ""
    for _ in range(len(message_as_numbers) // 3):
      decrypted_message += "".join([k for k, v in self.str_dict.items() if (v == message_as_numbers[index : end_index])])
      index = index + 3
      end_index = end_index + 3
    return decrypted_message

  # Gera a chave PSK para os usuários.
  def generate_psk(self):
    self.key = int(pow(self.incoming_x, self.secret, self.p))
    return self.key
  
  # set do x que chega, aqui apelidado de y
  def set_incoming_x(self, y):
    self.incoming_x = y
  
  # get do x que chega ao cliente.
  def get_incoming_x(self):
    return self.incoming_x
  
  # retornar o x para usar no socket.
  def get_x(self):
    return self.x

"""
# Testando a classe
if __name__ == '__main__':
  p = 197  # conhecido publicamente
  q = 151  # meu Alpha combinado
  dh1 = DiffieHellman(p, q, 199)
  dh2 = DiffieHellman(p, q, 157)
  
  dh1.calc_x()
  dh2.calc_x()
  
  dh1.set_incoming_x(dh2.x)
  dh2.set_incoming_x(dh1.x)
  
  dh1.generate_psk()
  dh2.generate_psk()
  
  encrypted_message = dh1.encrypt_with_key("abc", dh1.key)

  print(f"Mensagem encriptada por A é : {encrypted_message}")
  print(f"Mensagem descriptografada por B é :{dh2.decrypt_with_key(encrypted_message, dh2.key)}")
  print(f"O valor de PSK_A é: {dh1.key}")
  print(f"O valor de PSK_B é {dh2.key}")
"""