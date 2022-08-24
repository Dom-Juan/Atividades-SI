# -*- coding: utf-8 -*-

"""
  -> author: Juan Cardoso da Silva
"""

import sys        # utilizado para sair do programa de maneira correta.
import time       # verificar o tempo de execução do programa.
import binascii   # ajudar na conversão de binários para decimais e vise versa.
import os.path    # abrir o arquivo no computador.
import struct     # struct para empacotar bytes e desempacota-los depois, usado no calculo da sha1

# Bibliografia para fazer SHA1: https://en.wikipedia.org/wiki/SHA-1
# Bibliografia para fazer MD5:  https://en.wikipedia.org/wiki/MD5

# Inicio MD5
# tabela de constantes de números primos para ser utilizado no algoritmo.
s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14,
  20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

# tabela de constantes de pseudo números primos para ser utilizado no algoritmo.
t = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
    0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
    0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
    0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
    0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039,
    0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
    0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
    0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

# geração de um número inteiro de 32 bits, o binario como estamos recebendo está na forma 1000, ao rodar
#resulta em 1000, porem queremos um inteiro de 32 bits, essa função realiza essa conta.
def left_circular_shift(k, bits):
  bits = bits % 32
  k = k % (2**32)
  upper = (k << bits) % (2**32)
  result = upper | (k >> (32 - (bits)))
  return result

# Faz a divisão de blocos em chunks(pedaços) de bits para números inteiros a partir de bits.
def block_divide(block, chunks):
  size = len(block) // chunks
  # retorna um número inteiro convertido do binário do tipo little endian.
  return [
    int.from_bytes(block[i * size:(i + 1) * size], byteorder="little")
    for i in range(chunks)
]

# Processamento de bloco.
# Funções que ajudam a misturar a mensagem resultada das operações realizadas previamente.
# Os operadores utilizados são comparadores de binário.
def F(X, Y, Z): # Rodada de operações 1: B AND C OR (NOT B) AND D
  return((X & Y) | ((~X) & Z))

def G(X, Y, Z): # Rodada de operações 2: B AND D OR C AND (NOT D)
  return((X & Z) | (Y & (~Z)))

def H(X, Y, Z): # Rodada de oprações 3: B XOR C XOR D
  return(X^Y^Z) 

def I(X, Y, Z): # Rodada de oprações 4: C XOR B OR (NOT D)
  return(Y^(X | (~Z)))

# Aqui ocorre a compressão dos valores, onde:
# > t é um número da constante table
# > s é um número da constante de vedor de números primos usado no circular shift value.
# > a, b, c, d são valores de resultados anteriores.
def FF(a, b, c, d, M, s, t):
  return(b + left_circular_shift((a+F(b,c,d)+M+t), s)) # Rodada 1: realizando as adições e no final o shift rotate com o valor s atual.

def GG(a, b, c, d, M, s, t): 
  return(b + left_circular_shift((a+G(b,c,d)+M+t), s))  # Rodada 2

def HH(a, b, c, d, M, s, t):
  return(b + left_circular_shift((a+H(b,c,d)+M+t), s))  # Rodada 3

def II(a, b, c, d, M, s, t):
  return(b + left_circular_shift((a+I(b,c,d)+M+t), s))  # Rodada 4
# Processamento de bloco.

# função para formatar certinho os numeros do hexadecimal para bits.
def format_8(number):
  big_hex = "{0:08x}".format(number)
  b_inverse = binascii.unhexlify(big_hex)
  return ("{0:08x}".format(int.from_bytes(b_inverse, byteorder='little')))

# retorna o tamanho da string de bits
def bit_len(bit_string):
  return (len(bit_string)*8)

# Encriptar Strings
def create_md5(str, print_result=None):
  if(print_result == None):
    print("   >  Execução: create_md5(str)\n=======================================")
  hashed_str_md5 = ""
  start_time = time.time()  # início do programa, onde começa a realizar as contas
  # realizando o padding da string
  data_len = bit_len(str)%(2**64)         # calculando o tamanho da mensagem
  data = str + b'\x80'                    # adicionando o valor '1' em bits para nosso texto.
  zero_pad = (448 - (data_len+8)%512)%512 # em seguida criamos valores 0 até alcançar o padding da nossa mensagem.
  zero_pad //= 8                          # ajusta o tamanho para o padding ser inserido a seguir.
  # adiciona o padding e a notação little endian confomre o algoritmo pede para realização das contas (utilizando bits menos significatidos)
  data = data + b'\x00'*zero_pad + data_len.to_bytes(8,byteorder='little')
  data_len = bit_len(data)  # tamanho total da nossa mensagem.
  n = data_len//512         # divisão por 512 para garantir que o número de iterações seja pertencente a tabela multiplicadores de 512 para as contas.
  
  # Como a mensagem é quebrada em blocos de 512 bits cada, são utilizado 4 buffers de 32 bits, sendo eles "palavras" em hexadecimal fixos em i = 0.
  #como estou trabalho com little endians nas contas, esses valores hexadecimais abaixo foram trocados de ordem para bater nos valores abaixo.
  # Variáveis de cadeia.
  A = 0x67452301  # 01 23 45 67
  B = 0xefcdab89  # fe dc ba 98
  C = 0x98badcfe  # 89 ab cd ef
  D = 0x10325476  # 76 54 32 10

  # cada bloco abaixo é quebrado em sub blocos de 16 contendo 32 bits cada.
  for i in range(0, n):
    a, b, c, d = A, B, C, D
    block = data[i * 64 : (i + 1) * 64] # pegando um bloco.
    M = block_divide(block, 16)         # dividindo e achando os sub-blocos, armazenados em M.
    # iniciando o calculo dos rounds
    
    # Execução do algoritmo segue como:
    # > Temos 4 rodadas de operações, cada 1 deles utilizando todos 16 sub-blocos, usando nosso array de shift value e tablea de pseudonúmeros.
    # > B, C e D são realizados em processos não linearas para depois realizar a adição em A.
    # > A é adicionado com B, C, D, o resultado é somado ao sub-block atual de M, a table T e depois o shift value é realizado e fazendo uma ultima adição.
    # > O pseudo-número de T é adiucionado em A, a ultima adição é colocado em B, o shift em C e o processamento não linear em D.
    # > O processo não linear, PRECISA ser diferente toda rodada
    # inicio das rodadas
    a = FF( a,b,c,d, M[0], s[0], t[0] )
    d = FF(d, a, b, c, M[1], s[1], t[1])
    c = FF(c, d, a, b, M[2], s[2], t[2])
    b = FF(b, c, d, a, M[3], s[3], t[3])
    
    a = FF(a, b, c, d, M[4], s[4], t[4])
    d = FF(d, a, b, c, M[5], s[5], t[5])
    c = FF(c, d, a, b, M[6], s[6], t[6])
    b = FF(b, c, d, a, M[7], s[7], t[7])
    
    a = FF(a, b, c, d, M[8], s[8], t[8])
    d = FF(d, a, b, c, M[9], s[9], t[9])
    c = FF(c, d, a, b, M[10], s[10], t[10])
    b = FF(b, c, d, a, M[11], s[11], t[11])
    
    a = FF(a, b, c, d, M[12], s[12], t[12])
    d = FF(d, a, b, c, M[13], s[13], t[13])
    c = FF(c, d, a, b, M[14], s[14], t[14])
    b = FF(b, c, d, a, M[15], s[15], t[15])
    
    a = GG(a, b, c, d, M[1], s[16], t[16])
    d = GG(d, a, b, c, M[6], s[17], t[17])
    c = GG(c, d, a, b, M[11], s[18], t[18])
    b = GG(b, c, d, a, M[0], s[19], t[19])
    
    a = GG(a, b, c, d, M[5], s[20], t[20])
    d = GG(d, a, b, c, M[10], s[21], t[21])
    c = GG(c, d, a, b, M[15], s[22], t[22])
    b = GG(b, c, d, a, M[4], s[23], t[23])
    
    a = GG(a, b, c, d, M[9], s[24], t[24])
    d = GG(d, a, b, c, M[14], s[25], t[25])
    c = GG(c, d, a, b, M[3], s[26], t[26])
    b = GG(b, c, d, a, M[8], s[27], t[27])
    
    a = GG(a, b, c, d, M[13], s[28], t[28])
    d = GG(d, a, b, c, M[2], s[29], t[29])
    c = GG(c, d, a, b, M[7], s[30], t[30])
    b = GG(b, c, d, a, M[12], s[31], t[31])
    
    a = HH(a, b, c, d, M[5], s[32], t[32])
    d = HH(d, a, b, c, M[8], s[33], t[33])
    c = HH(c, d, a, b, M[11], s[34], t[34])
    b = HH(b, c, d, a, M[14], s[35], t[35])
    
    a = HH(a, b, c, d, M[1], s[36], t[36])
    d = HH(d, a, b, c, M[4], s[37], t[37])
    c = HH(c, d, a, b, M[7], s[38], t[38])
    b = HH(b, c, d, a, M[10], s[39], t[39])
    
    a = HH(a, b, c, d, M[13], s[40], t[40])
    d = HH(d, a, b, c, M[0], s[41], t[41])
    c = HH(c, d, a, b, M[3], s[42], t[42])
    b = HH(b, c, d, a, M[6], s[43], t[43])
    
    a = HH(a, b, c, d, M[9], s[44], t[44])
    d = HH(d, a, b, c, M[12], s[45], t[45])
    c = HH(c, d, a, b, M[15], s[46], t[46])
    b = HH(b, c, d, a, M[2], s[47], t[47])
    
    a = II(a, b, c, d, M[0], s[48], t[48])
    d = II(d, a, b, c, M[7], s[49], t[49])
    c = II(c, d, a, b, M[14], s[50], t[50])
    b = II(b, c, d, a, M[5], s[51], t[51])
    
    a = II(a, b, c, d, M[12], s[52], t[52])
    d = II(d, a, b, c, M[3], s[53], t[53])
    c = II(c, d, a, b, M[10], s[54], t[54])
    b = II(b, c, d, a, M[1], s[55], t[55])
    
    a = II(a, b, c, d, M[8], s[56], t[56])
    d = II(d, a, b, c, M[15], s[57], t[57])
    c = II(c, d, a, b, M[6], s[58], t[58])
    b = II(b, c, d, a, M[13], s[59], t[59])
    
    a = II(a, b, c, d, M[4], s[60], t[60])
    d = II(d, a, b, c, M[11], s[61], t[61])
    c = II(c, d, a, b, M[2], s[62], t[62])
    b = II(b, c, d, a, M[9], s[63], t[63])
    
    A = (A + a) % 2**32
    B = (B + b) % 2**32
    C = (C + c) % 2**32
    D = (D + d) % 2**32
  hashed_str_md5 = format_8(A) + format_8(B) + format_8(C) + format_8(D)  # formatando o resultado para mostrara a hash no terminal.
  end_time = time.time() - start_time # fim de execução e obtendo o tempo total de execução.
  
  if(print_result is None):
    print(f"Resultado da md5 é:{hashed_str_md5}")
    print(f"Tamanho do resultado da hash é: {len(hashed_str_md5)}")
    print(f"Demorou {end_time} para completar a encripção da string fornecida")

  return hashed_str_md5
# Fim MD5

# Inicio SHA1
# Processamento de bits
def sha1_f(B, C ,D): # Rodada de operações 1
  return ((B & C) | ((~B) & D))

def sha1_g(B, C ,D): # Rodada de operações 2
  return (B ^ C ^ D)

def sha1_h(B, C ,D): # Rodada de operações 3
  return ((B & C) | (B & D) | (C & D))

def sha1_i(B, C ,D): # Rodada de operações 4
  return (B ^ C ^ D)
# Processamento de bits
def sha1_rotate(x, c):  # rotação de bits.
  return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

def create_sha1(str, print_result=None):  
  if(print_result == None):
    print("   >  Execução: create_sha1(str)\n=======================================")
  # h[0] -> A, h[1] -> 2, h[2] -> 3, h[3] -> B
  h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0] 
  data = str                                                                # Criando a minha variável de dados
  start_time = time.time()                                                  # início do programa, onde começa a realizar as contas
  # realizando o padding da string
  padding = b"\x80" + b"\x00" * (63 - (len(data) + 8) % 64)                 # Criando o padding '1' no tamanho de 64 bits
  padded_data = data + padding + struct.pack(">Q", 8 * len(data))           # Adiconando esse padding ao dado e empacotando ele, 8 bits -> 1
  blocks = [padded_data[i : i + 64] for i in range(0, len(padded_data), 64)]# Criando um padding no final adicional de 0.
  # Percorrendo os blocos e pegando cada bloco.
  for block in blocks:
    w = list(struct.unpack(">16L", block)) + [0] * 64 # desempacotando o padding e o seu tamanho original 1 - > 8.
    # percorrendo os blocos de 16 em 16 e fazendo a rotação
    for i in range(16, 80):
      w[i] = sha1_rotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1)
    expanded_block = w
    A, B, C, D, E = h
    for i in range(0, 80):
      if 0 <= i < 20:
        f = sha1_f(B, C, D)
        k = 0x5A827999
      elif 20 <= i < 40:
        f = sha1_g(B, C, D)
        k = 0x6ED9EBA1
      elif 40 <= i < 60:
        f = sha1_h(B, C, D)
        k = 0x8F1BBCDC
      elif 60 <= i < 80:
        f = sha1_i(B, C, D)
        k = 0xCA62C1D6
      # Calcula os novos valores de A, B, C, D, E.
      A, B, C, D, E = (
        sha1_rotate(A, 5) + f + E + k + expanded_block[i] & 0xFFFFFFFF,
        A,
        sha1_rotate(B, 30),
        C,
        D,
      )
    h = ( # Adiciona os novos valores de h, em operações em hexadecimal e binário.
      h[0] + A & 0xFFFFFFFF,
      h[1] + B & 0xFFFFFFFF,
      h[2] + C & 0xFFFFFFFF,
      h[3] + D & 0xFFFFFFFF,
      h[4] + E & 0xFFFFFFFF,
    )
  hashed_data_sha1 = "%08x%08x%08x%08x%08x" % tuple(h)  # formatação em hexadecimal
  end_time = time.time() - start_time                   # fim de execução e obtendo o tempo total de execução.
  if(print_result is None):
    print(f"Resultado da md5 é:{hashed_data_sha1}")
    print(f"Tamanho do resultado da hash é: {len(hashed_data_sha1)}")
    print(f"Demorou {end_time} para completar a encripção da string fornecida")
  return hashed_data_sha1
# Fim SHA1

def md5_hash_and_digest(data, command):
  d = bytes(data, 'ascii') # codando para binário as string.  
  return create_md5(d, command)     # criando a md5

def sha1_hash_and_digest(data, command):
  d = bytes(data, 'ascii') # codando para binário as string.  
  return create_sha1(d, command)     # criando a md5

def main(args):
  error = "Argumentos invalidos"
  if(len(args) > 1):
    if (args[1] == '-md5' and args[2] == '-file'): # caso queira abrir um arquivo para verificar sua hash
      if (len(args) > 2):
        file_name = sys.argv[3]
        if not os.path.exists(file_name):
          print("Arquivo não existe...")
          sys.exit(1)
        file_pointer = open(file_name,"rb")
        data = file_pointer.read()
        create_md5(data)  # criando a md5
        file_pointer.close()  # fechando o ponteiro de entrada
      else:
        print(error)
        sys.exit(1)
    elif (args[1] == '-md5' and args[2] != '-file'): # caso seja digitado para gerar a hash de uma string
      data = bytes(args[2], 'ascii') # codando para binário as string.  
      create_md5(data)  # criando a md5
    elif (args[1] == '-sha1' and args[2] == '-file'):
      if (len(args) > 2):
        file_name = sys.argv[3]
        if not os.path.exists(file_name):
          print("Arquivo não existe...")
          sys.exit(1)
        file_pointer = open(file_name,"rb")
        data = file_pointer.read()
        result = create_sha1(data)
        file_pointer.close()
        print(result)
      else:
        print(error)
        sys.exit(1)
    elif (args[1] == '-sha1' and args[2] != '-file'):
      print(args[2])
      data = bytes(args[2], 'ascii')
      result = create_sha1(data)
      print(result)
      # print(format_sha1(result))
    else: 
      print("Algo deu errado, use:\n> 'py main.py -md5 string' para MD5\n> 'py main.py -sha1 string' para SHA1")
      print("\nCaso queira verificar arquivos, use:\n> 'py main.py -md5 -file path' para MD5\n> 'py main.py -sha1 -file path' para SHA1")
  else: 
    print("Algo deu errado, use:\n> 'py main.py -md5 string' para MD5\n> 'py main.py -sha1 string' para SHA1")
    print("\nCaso queira verificar arquivos, use:\n> 'py main.py -md5 -file path' para MD5\n> 'py main.py -sha1 -file path' para SHA1")
    return 1
  return 0


if __name__ == '__main__':
  print(f"Argumentos inseridos: {sys.argv}")
  if(main(sys.argv) == 0):
    sys.exit(0)
