# -*- coding: utf-8 -*-

"""
  -> author: Juan Cardoso da Silva - 171257138
  -> author: Guilherme de Aguiar Pacianotto - 181251019
"""

# imports do sistema
import socket as s
import os
import json
import threading as thread

# Import de bibliotecas locais
from rsa_2psk import RSA
from dh import DiffieHellman, gen_prime_numbers, binary_search, sieve
#os.system("cls")

print('\n[===================================================]\n')
print('\t\t Chat com Criptografia - DH e RSA')
print('\n[===================================================]\n')

# Setando o ip e porta da conexão atual.
ip = "127.0.0.1"
port = 14000

# Setando o ip e porta do alvo a conectar.
target_ip = "127.0.0.1"
target_port = 15000

s1 = s.socket(s.AF_INET, s.SOCK_DGRAM) # cria o socket com conexão UDP.
s1.bind((ip, port)) # vincula a porta e ip a este socket.

# Input do segredo do DH.
secret = int(input("Digite seu secret_key >: "))
response = gen_prime_numbers() # gerando numéros primos q atendam as condições p * q > 400, p != q e p e q serem primos.
p = response[0] # p pego
q = response[1] # q pego
diffie_hellman = DiffieHellman(p, q, secret)
diffie_hellman.calc_x() # Calculo do diffie hellman

primes = sieve([])  # estudar remover depois.

p_rsa = p # Q do RSA, os mesmos do DH.
q_rsa = q # Q do RSA, os mesmos do DH.

# Trocando as chaves e gerando a chave final.
def gen_keys():
  print("\t\t * Trocando as chaves públicas do DH. *")
  print("Esperando cliente...")
  msg = s1.recvfrom(2048)               # recebe a mensagem de tamanho até 2048.
  addr = msg[1]                         # Pegando o endereço recebido.
  msg = msg[0].decode()                 # Decode da mensagem em bytes.
  data = json.loads(msg)                # "Descompactando" o json enviado
  data1 = data.get("incoming_x")        # Pegando o valor Y chegando pelo socket.
  print(f"Sua Chave pública: {diffie_hellman.get_x()}")
  print("\n Chave pública de ["+str(addr)+"@]:", data1)
  print(type(data1))
  e = json.dumps({"incoming_x": diffie_hellman.get_x()})
  e = e.encode()                            # Encoding parar bytes da mensagem em json "compactada"
  s1.sendto(e, (target_ip, target_port))    # envia as informações para o alvo.
  diffie_hellman.set_incoming_x(data1)      # set no valor Y para calcular o PSK.
  diffie_hellman.generate_psk()             # Calculando o PSK.
  # Retornando o primo mais próximo, não utilizado no algoritmo, realizado outra lógica.
  return binary_search(0, len(primes) - 1, diffie_hellman.key, primes)

# chamando a função para trocar as chaves com o DH cusando socket.
gen_keys()

print("P e Q do RSA", p_rsa, q_rsa)
# Iniciando a classe RSA e começando o cálculo.
person_b_rsa = RSA(p_rsa, q_rsa)
person_b_rsa.calc_n()
person_b_rsa.calc_euler_totient()
person_b_rsa.calc_public_key(diffie_hellman.key)
person_b_rsa.calc_private_key()

# Realiza o envio de dados:
def connection():
  # Mostrando a thread e seu id no console.
  print(thread.current_thread().name)
  print(thread.get_ident())
  while(True):
    decrypted_message = ""
    try:
      print("Esperando resposta...")
      msg = s1.recvfrom(2048) # recebe a mensagem de tamanho até 2048.
      # se o texto do outro cliente for um comando de sair, avisa que ele saiu.
      print(msg)
      msg = msg[0].decode()                                 # Decode da mensagem em bytes.
      data = json.loads(msg)                                # "Descompactando" o json enviado.
      msg = data.get("data")                                # pegando a chave da criptografia.
      decrypted_message = person_b_rsa.decrypt_message(msg) # Desencriptando a mensagem recebida com RSA.
      print("\n Recebido de ["+str(target_ip)+"@"+str(target_port)+"]: ", decrypted_message)
    except s.error: # passa o erro para ser printado caso este ocorra.
      print("Erro na conexão...", s.error)
    encrypted_data = ""
    try:
      data = str(input("["+str(target_ip)+"@"+str(target_port)+"]: ")).encode() # encriptando os dados.
      if data.decode() in {'[quit]', '[sair]'}:
        s1.close()
        os._exit(1) # termina o processo
      print(data.decode())
      data = person_b_rsa.encrypt_message(data.decode())  # encriptando a mensagem string com o RSA.
      encrypted_data = json.dumps({"data": data})
      encrypted_data = encrypted_data.encode()            # Encoding parar bytes da mensagem em json "compactada".
      s1.sendto(encrypted_data, (target_ip, target_port)) # envia as informações para o alvo.
      # se o texto enviado for um comando, sai do chat.
    except s.error: # passa o erro para ser printado caso este ocorra.
      print("Erro na conexão...", s.error)

# Iniciando as threads agora.
thread_3 = thread.Thread(target=connection, name='connection') # Thread que recebe a info

# Iniciando a threads.
thread_3.start()


