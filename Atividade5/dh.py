# -*- coding: utf-8 -*-

"""
  -> author: Juan Cardoso da Silva - 171257138
  -> author: Guilherme de Aguiar Pacianotto - 181251019
"""

import math
from random import randint

MAX = 10000;
# Array para armazenar primos mais próximos de até 10^6 de tamanho.

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

# Função de Sieve of Sundaram.
def sieve(primes):
  n = MAX;
  # No geral a função de Sieve of Sundaram produz uma quantidade de números primos menores que 2 * x + 2
  # dadao um x qualquer, vamos usar a chave do DH para gerar o mesmo número primo próximo para usar na chave do RSA.
  nNew = int(math.sqrt(n));
  # Este array é usado para separar numeros na forma: i + j + 2*i*j dos outros onde 1 <= i <= j
  marked = [0] * (int(n / 2 + 500));
  # elimina os indexes que não são iguais
  # produção de primos
  for i in range(1, int((nNew - 1) / 2) + 1):
      for j in range(((i * (i + 1)) << 1), (int(n / 2) + 1), (2 * i + 1)): marked[j] = 1;
  # Como 2 é o primeiro número primoSince 2 is a prime number
  primes.append(2);
  # Os primos restantes da forma 2 * i + 1 de maeira que marked[i] é falso.
  for i in range(1, int(n / 2) + 1):
    if (marked[i] == 0):
     primes.append(2 * i + 1);
  return primes

# Usando busca binária para achar o primos mais próximo menor que o valor autal.
def binary_search(left, right, n, primes):
  # condição segue como, se estamos no canto esquerdo ou canto direito do array de primes, então
  #retornamos os cantos do elemento antes e depois, até não exisitr mais números primos no array.
  if left <= right:
    mid = int((left + right) / 2)
  # se o n for um primo, então vamos ter que procurar um primo próximo dele no array de primos, 
  # se não for, devemos procurar o primo mais próximo.
  if mid == 0 or mid == len(primes) - 1:
    return primes[mid]
  # now if primes[mid]<n and primes[mid+1]>n
  # that means we reached at nearest prime
  # agora se os primos do meio menor que n e os primos de meio + 1 for maior que n, significa que
  #achamos o primo mais próximo.
  if primes[mid] == n:
    return primes[mid - 1]
  if primes[mid] < n and primes[mid + 1] > n:
    return primes[mid]
  if n < primes[mid]:
    return binary_search(left, mid - 1, n, primes)
  else:
    return binary_search(mid + 1, right, n, primes)
  return 0

class DiffieHellman:
  def __init__(self, p, alpha, secret) -> None:
    self.p = p            # Valor p
    self.alpha = alpha    # Valor Alpha
    self.secret = secret  # Secret único de cada cliente, não deve ser compartilhado
    self.x = 0            # Valor x calculado na geração da chave pública.
    self.incoming_x = 0   # Valor que é enviado para fazer o calculo da chave privada.
    self.key = 0          # Valor da chave.

  # Calcular o X
  def calc_x(self):
    self.x = int(pow(self.alpha, self.secret, self.p))

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


# Testando a classe
if __name__ == '__main__':
  p = 17  # conhecido publicamente
  q = 41  # meu Alpha combinado
  # Iniciando a classe, introduzindo os valores p, q e segredo.
  dh1 = DiffieHellman(p, q, 6)
  dh2 = DiffieHellman(p, q, 3)
  
  # Calculando os X
  dh1.calc_x() # Xa
  dh2.calc_x() # Xb
  
  # Trocando as X de cada pessoa.
  dh1.set_incoming_x(dh2.x) # A recebe Xb
  dh2.set_incoming_x(dh1.x) # B recebe Xa
  
  dh1.generate_psk()  # Gera a KEYa
  dh2.generate_psk()  # Gera a KEYb
  
  print(f"O valor de PSK_A é: {dh1.key}")
  print(f"O valor de PSK_B é {dh2.key}")
  # testes abaixo para serem utilizados no RSA.
  primes = sieve([])  # gerando um array de primos
  new_key1 = binary_search(0, len(primes) - 1, dh1.key, primes) # KEYa vai ser um primo mais proximo de KEYa_antigo
  new_key2 = binary_search(0, len(primes) - 1, dh2.key, primes) # KEYb vai ser um primo mais proximo de KEYb_antigo
  print(f"Primo próximo de Chave-de-A: {new_key1}, Primo próximo de Chave-de-B:{new_key2}")