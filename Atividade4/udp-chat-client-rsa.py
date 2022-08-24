# -*- coding: utf-8 -*-

"""
  -> author: Juan Cardoso da Silva - 171257138
  -> author: Guilherme de Aguiar Pacianotto - 181251019
"""

import socket as s
import threading as thread
import os
import json

from rsa_gen import gen_rsa_key, decrypt_rsa
from _thread import *
#os.system("cls")

print('\n[===================================================]\n')
print('\t\t Chat Simultâneo com encriptação RSA')
print('\n[===================================================]\n')

# Setando o ip e porta da conexão atual.
ip = str(input("Digite seu endereço IP >: "))
port = int(input("Digite a sua porta escolhida >: "))
print("\n Agora caso queira, espere a conexão ou inicie a conexão de outro cliente \n")

p = 793
q = 7393
# Setando o ip e porta do alvo a conectar.
receiving_ip = str(input("Digite o ip de um cliente >: "))
receiving_port = int(input("Digite a porta do cliente >: "))

secret = receiving_port = int(input("Digite seu secret_key >: "))
# Vinculando o socket agora:
s1 = s.socket(s.AF_INET, s.SOCK_DGRAM) # cria o socket com conexão UDP.

s1.bind((ip, port)) # vincula a porta e ip a este socket.

# Funções a serem utilizadas pelas threads:

# Realiza o envio de dados:
def send_data():
  # Mostrando a thread e seu id no console.
  print(thread.current_thread().name)
  print(thread.get_ident())
  encrypted_data = None
  while(True):
    try:
      data = input().encode() # encriptando os dados.
      if (data.decode() == '[quit]' or data.decode() == '[sair]'):
        os._exit(1) # termina o processo
      data = gen_rsa_key((p * q), [p, q], data.decode(), True)  # gerando resltado do RSA, uma chave p e dados D.
      # Compactando a mensagem em json para facilitar a minha vida.
      encrypted_data = json.dumps({"data": data[0], "data_string": data[1]})
      encrypted_data = encrypted_data.encode()  # Encoding parar bytes da mensagem em json "compactada"
      s1.sendto(encrypted_data, (receiving_ip, receiving_port)) # envia as informações para o alvo.
      # se o texto enviado for um comando, sai do chat.
    except s.error: # passa o erro para ser printado caso este ocorra.
      print("Erro na conexão...", s.error)

# Realiza a coleta de dados:
def get_data():
  # Mostrando a thread e seu id no console.
  print(thread.current_thread().name)
  print(thread.get_ident())
  decrypted_message = ""
  encrypted_data = ""
  while(True):
    try:
      print("Conexão Ativada!")
      msg = s1.recvfrom(2048) # recebe a mensagem de tamanho até 2048.
      # se o texto do outro cliente for um comando de sair, avisa que ele saiu.
      print(msg)
      msg = msg[0].decode()   # Decode da mensagem em bytes.
      data = json.loads(msg)  # "Descompactando" o json enviado.
      msg = data.get("data")  # pegando a chave da criptografia.
      data_string = data.get("data_string")     # Pegando a string encriptada
      print(msg)
      for item in msg:
        encrypted_data += str(item)
      msg = decrypt_rsa(encrypted_data, p, q, data_string)
      print(msg)
      for item in msg:
        decrypted_message += chr(item)
      if (decrypted_message == '[quit]' or decrypted_message == '[sair]'):
        print("Cliente desconectado.")
        os._exit(1) # termina o processo.
      print("\n Recebido de ["+str(receiving_ip)+"@"+str(receiving_port)+"]: ", decrypted_message)
    except s.error: # passa o erro para ser printado caso este ocorra.
      print("Erro na conexão...", s.error)

# Iniciando as threads agora.
thread_1 = thread.Thread(target=send_data, name='send_data') # Thread que envia a info.
thread_2 = thread.Thread(target=get_data, name='get_data') # Thread que recebe a info

# Iniciando as threads.
thread_1.start()
thread_2.start()

