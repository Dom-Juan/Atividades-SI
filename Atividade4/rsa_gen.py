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

def gen_rsa_key(modulus_n, dict, data, no_print=False):
  p, q = dict[0], dict[1]
  euler_totient = (p - 1) * (q - 1)
  coprimes = [
    x for x in range(2, euler_totient) if(math.gcd(x, euler_totient) == 1)
  ]
  e = coprimes[randint(0, len(coprimes) - 1)]
  d, text = 0, []
  for k in range(1, e):
    if (k * euler_totient + 1) % e == 0:
      d = (k * euler_totient + 1) // e
      break
  c = []
  print("\np = {0} q = {1} n = {2} euler toitent = {3} e = {4} d = {5}".format(p, q, modulus_n, euler_totient, e, d))
  if(no_print == False):
    plain_text = [x for x in input("Digite qualquer coisa: ")]
    print(plain_text)
    for x in plain_text:
      c.append((ord(x) ** e) % modulus_n)
    print(c)
  else:
    data = [x for x in data]
    for x in data:
      c.append((ord(x) ** e) % modulus_n)
  return [c, d]

def decrypt_rsa(key, p, q, d):
  text = []
  data = int(key)
  print(data, type(data), d, type(d), (p * q), type((p * q)))
  for x in data:
    r = (key ** d) % (p * q)
    print(r)
    text.append(chr(r))
  return text

def rsa_start():
  result = gen_prime_numbers()
  gen_rsa_key((result[0]*result[1]), result, "", False)
  
if __name__ == '__main__':
  rsa_start()