# -*- coding: utf-8 -*-

"""
  -> author: Juan Cardoso da Silva - 171257138
  -> author: Guilherme de Aguiar Pacianotto - 181251019
"""

import socket as s
import os
import json

from dh import DiffieHellman, gen_prime_numbers, is_prime
from _thread import *
#os.system("cls")

print('\n[===================================================]\n')
print('\t\t Criptografia com DH')
print('\n[===================================================]\n')

# Setando o ip e porta da conexão atual.
ip = "127.0.0.1"
port = 15000

# Setando o ip e porta do alvo a conectar.
target_ip = "127.0.0.1"
target_port = 14000

s1 = s.socket(s.AF_INET, s.SOCK_DGRAM) # cria o socket com conexão UDP.
s1.bind((ip, port)) # vincula a porta e ip a este socket.

secret = int(input("Digite seu secret_key >: "))
response = gen_prime_numbers()
p = response[0]
q = response[1]
diffie_hellman = DiffieHellman(p, q, secret)
diffie_hellman.calc_x() # Calculo do diffie hellman

def gen_keys():
  print(f"Sua Chave pública: {diffie_hellman.get_x()}")
  e = json.dumps({"incoming_x": diffie_hellman.get_x()})
  e = e.encode()  # Encoding parar bytes da mensagem em json "compactada"
  s1.sendto(e, (target_ip, target_port)) # envia as informações para o alvo.
  msg = s1.recvfrom(2048) # recebe a mensagem de tamanho até 2048.
  msg = msg[0].decode()   # Decode da mensagem em bytes.
  data = json.loads(msg)  # "Descompactando" o json enviado.
  incoming_x = data.get("incoming_x")       # Pegando o valor Y chegando pelo socket.
  print(incoming_x)
  diffie_hellman.set_incoming_x(incoming_x) # set no valor Y para calcular o PSK
  diffie_hellman.generate_psk()             # Calculando o PSK
  # Vinculando o socket agora:
  return True

gen_keys()

def connection():
  while(True):
    encrypted_data = None
    try:
      data = str(input("["+str(target_ip)+"@"+str(target_port)+"]: ")).encode() # encriptando os dados.
      if data.decode() in {'[quit]', '[sair]'}:
        s1.close()
        os._exit(1) # termina o processo
      data = diffie_hellman.encrypt_with_key(data.decode(), diffie_hellman.key)
      encrypted_data = json.dumps({"data": data, "incoming_x": diffie_hellman.get_x()})
      encrypted_data = encrypted_data.encode()  # Encoding parar bytes da mensagem em json "compactada"
      s1.sendto(encrypted_data, (target_ip, target_port)) # envia as informações para o alvo.
      # se o texto enviado for um comando, sai do chat.
    except s.error: # passa o erro para ser printado caso este ocorra.
      print("Erro na conexão...", s.error)
    try:
      print("Esperando resposta...")
      msg = s1.recvfrom(2048) # recebe a mensagem de tamanho até 2048.
      # se o texto do outro cliente for um comando de sair, avisa que ele saiu.
      decrypted_message = ""
      # se o texto do outro cliente for um comando de sair, avisa que ele saiu.
      print(msg)
      msg = msg[0].decode()   # Decode da mensagem em bytes.
      data = json.loads(msg)  # "Descompactando" o json enviado.
      msg = data.get("data")  # pegando a chave da criptografia.
      decrypted_message = diffie_hellman.decrypt_with_key(msg, diffie_hellman.key)
      print("\n Recebido de ["+str(target_ip)+"@"+str(target_port)+"]: ", decrypted_message)
    except:
      print("Erro na conexão...", s.error)


connection()
"""
decrypted_message = ""
try:
  print("Conexão Ativada!")
  msg = s2.recvfrom(2048) # recebe a mensagem de tamanho até 2048.
  # se o texto do outro cliente for um comando de sair, avisa que ele saiu.
  print(msg)
  msg = msg[0].decode()   # Decode da mensagem em bytes.
  data = json.loads(msg)  # "Descompactando" o json enviado.
  msg = data.get("data")  # pegando a chave da criptografia.
  decrypted_message = diffie_hellman.decrypt_with_key(msg, diffie_hellman.key)
  print("\n Recebido de ["+str(receiving_ip)+"@"+str(receiving_port)+"]: ", decrypted_message)
except s.error: # passa o erro para ser printado caso este ocorra.
  print("Erro na conexão...", s.error)
"""

