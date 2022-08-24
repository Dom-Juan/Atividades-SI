# -*- coding: utf-8 -*-

"""
  -> author: Juan Cardoso da Silva - 171257138
  -> author: Guilherme de Aguiar Pacianotto - 181251019
"""

import math

from random import randint

class RSA:
  def __init__(self, p, q):
    self.p = p
    self.q = q
    self.n = 0
    self.euler_toitent = 0
    self.public_key = 0
    self.private_key = 0
    self.e = 0
    self.table = {'a': "101", 'b': "102", 'c': "103", 'd': "104", 'e': "105", 'f': "106", 'g': "107", 'h': "108", 
      'i': "109", 'j': "110", 'k': "111", 'l': "112", 'm': "113", 'n': "114", 'o': "115", 'p': "116", 
      'q': "117", 'r': "118", 's': "119", 't': "120", 'u': "121", 'v': "122", 'w': "123", 'x': "124", 
      'y': "125", 'z': "126", " ": "127", 'A': "201", 'B': "202", 'C': "203", 'D': "204", 'E': "205", 
      'F': "206", 'G': "207", 'H': "208", 'I': "209", 'J': "210", 'K': "211", 'L': "212", 'M': "213", 
      'N': "214", 'O': "215", 'P': "216", 'Q': "217", 'R': "218", 'S': "219", 'T': "220", 'U': "221", 
      'V': "222", 'W': "223", 'X': "224", 'Y': "225", 'Z': "226", ",": "301", ".": "302", '[':"303", ']':"304"
    } # dicionário de strings para gerar a mensagem criptografada.
  
  def calc_n(self):
    self.n = self.p * self.q
  
  def calc_euler_toitent(self):
    self.euler_toitent = (self.p - 1) * (self. q - 1)
  
  def calc_public_key(self):
    coprimes = [
      x for x in range(2, self.euler_toitent) if(math.gcd(x, self.euler_toitent) == 1)
    ]
    self.e = coprimes[randint(0, len(coprimes) - 1)]
    self.public_key = [self.n, self.e]
    return self.public_key
  
  def encrypt_message(self, message):
    return [
      int(pow(int(self.table[i]), self.public_key[1], self.public_key[0]))
      for i in message
    ]
  
  def calc_private_key(self):
    d = 0
    for k in range(1, self.e):
      if (k * self.euler_toitent + 1) % self.e == 0:
        d = (k * self.euler_toitent + 1) // self.e
        break
    print(d)


if __name__ == '__main__':
  rsa_alg = RSA(17, 41)
  rsa_alg.calc_n()
  rsa_alg.calc_euler_toitent()
  print(rsa_alg.calc_public_key())
  print(rsa_alg.encrypt_message("teste"))
  rsa_alg.calc_private_key()