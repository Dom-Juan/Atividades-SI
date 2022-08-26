Ordem de execução:
	> iniciar udp-b.py com: python udp-b.py
	> iniciar udp-a.py com: python udp-a.py
	> introduzir os segredos/chaves privadas
	> digitar p e q para ambos lados, sendo os mesmos números(primeiro em udp-b.py depois em udp-a.py, por ser udp, não deve ter diferença em execução
mas por via das dúvidas, seguir essa ordem)
	> pronto, ambos lados vão acessar as classes dh para fazer os calculos, seguido depois da troca da chave intermediaria e por fim o calculo da chave final
	> com isso o RSA é iniciado e criados suas chaves
	> o programa estará pronto para mandar mensagens entre usuários.