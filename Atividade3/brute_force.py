# -*- coding: utf-8 -*-

"""
  -> author: Juan Cardoso da Silva
"""

import sys   # importado para remover o programa corretamente
import time  # importado para calcular o tempo de execução do algoritmo

# import de bibliotecas específicas
from random import randint            # randint do python
from main import md5_hash_and_digest  # calculo de m5
from main import sha1_hash_and_digest # calculo de sha1

# pool de word list
word_list = [
  "abba", "abacate", "carolina", "dados", "esperanto", "fatos", "gatos", "hen", "italiano",
  "jogo","kaka", "loading", "not", "mario", "oeste", "porco", "queijo", "rato", "sapo", "torre",
  "uva", "vaca", "wario", "xarope", "yago", "zebra", "234", "cxzv", "sfdadf", "testecrack"
]

# lista de hashes, aqui quando o algoritmo executar, vai sobrar apenas as hashes rejeitadas
hash_list = []

# auxiliar para quebrar o loop quando o vetor ficar limpo de hashes;
hash_list_aux = []

def brute_force(h, method):
  found = []  # vetor para formata as respostas.
  for word in word_list:  # criando o vetor de hashes para guardas as hashes que foram descartadas.
    hh = md5_hash_and_digest(word, "no-print") if(method == "-md5")  else sha1_hash_and_digest(word, "no-print")
    hash_list.append(hh)
    hash_list_aux.append(hh)
  start_time = time.time()  # início do tempo
  # data = md5_hash_and_digest(data) if(method == "md5")  else sha1_hash_and_digest(data)
  while(True): # loop pra continuar achando as hashs.
    word = word_list[randint(0, len(word_list)-1)].rstrip()
    # Calcula o valor da hash baseado no método passado, md5 ou sha1.
    current_hash = md5_hash_and_digest(word, "no-print") if(method == "-md5")  else sha1_hash_and_digest(word, "no-print")
    if(current_hash == h):  # Achou a chave correspondente.
      found.append(current_hash)      # adiciona no vetor resposta.
      found.append(word)              # adiciona no vetor resposta.
      hash_list.remove(current_hash)  # remove da lista de hashes rejeitadas.
      word_list.remove(word)          # remove da lista de palavras.
      break
    else:
      hash_list_aux.remove(current_hash)  # remove da lista de hashes auxiliares.
      if(not hash_list_aux):  # Se arrancar todas as hashes da lista de auxiliares, é pq a palavra da pool não contém a resposta.
        print("Não foi possivel achar a chave na pool de word list")
        break
  end_time = time.time() - start_time # calculando tempo final
  titles = ["Hash list (rejeitadas)", "Word List (rejeitados)"]
  res = "\n".join("|{:>32} | {:>32}|".format(x, y) for x, y in zip(hash_list, word_list)) # formatação do print de tabela: hash | word
  print("|{:>32} | {:>32}|".format(titles[0], titles[1])) # formatção de titulo
  print(res)  # print do resultado.
  print("\n************************************************************")
  print(f"Achado:")
  print("|{:>32} | {:>32}|".format("Hash", "Password")) # formatação do titulo
  print("|{:>32} | {:>32}|".format(found[0], found[1])) # print da resposta
  print(f"Tempo de execução: {end_time}")

def main(args):
  error = "Argumentos invalidos"
  print("> Execução: main(args)")
  if(len(args) > 2):  # caso os argumentos sejam maior que 2
    if (args[1] == '-md5'):
      h = args[2]
      brute_force(h, "-md5")  # Fazendo o brute force.
    elif(args[1] == '-sha1'):
      h = args[2]
      brute_force(h, "-sha1")  # Facendo o brute force.
    else:
      print(error)
      print("Algo deu errado, use:\n> 'py brute_force.py -md5 hash' para MD5\n> 'py brute_force.py -sha1 hash' para SHA1")
      sys.exit(1)
  else:
    print(error)
    print("Algo deu errado, use:\n> 'py brute_force.py -md5 hash' para MD5\n> 'py brute_force.py -sha1 hash' para SHA1")
    sys.exit(1)

if __name__ == '__main__':
  print(f"Argumentos inseridos: {sys.argv}")
  if(main(sys.argv) == 0):
    sys.exit(0)
