UNSEC Tool

📚 Documentação: UNSEC - Monitor de Tráfego de Rede

O UNSEC é uma ferramenta de linha de comando em Python, projetada para capturar e analisar pacotes de rede utilizando a biblioteca Scapy. Sua principal função é demonstrar como dados de serviços legados e sem criptografia podem ser facilmente interceptados em uma rede. O programa oferece uma interface interativa para realizar diferentes tipos de monitoramento de forma simples e intuitiva.


⚙️ Pré-requisitos

Para executar o UNSEC, você precisa ter Python 3 e as seguintes bibliotecas instaladas: Scapy, Colorama e Keyboard.

Instalação das Bibliotecas
Abra seu terminal ou prompt de comando e execute:

    Bash

    pip install scapy
    pip install colorama
    pip install keyboard


🚀 Como Usar o UNSEC

Baixe ou Clone o Repositório: Obtenha o arquivo UNSEC.py para sua máquina.

Navegue até a Pasta: Abra o terminal e vá para o diretório onde o arquivo está salvo.

Execute o Script: O Scapy requer privilégios de administrador para capturar pacotes de rede. Execute o script da seguinte maneira:

    Bash

    # No Linux/macOS
    sudo python3 UNSEC.py

    # No Windows (abra o Prompt de Comando como Administrador)
    python UNSEC.py
    
📜 Funcionalidades e Uso

Ao iniciar o UNSEC, você será recebido por um menu interativo com as seguintes opções de monitoramento:

TCP Insecure Scan: Inicia a captura de pacotes TCP em portas conhecidas por serviços que transmitem dados sem criptografia. O filtro está configurado para as portas 21 (FTP), 23 (Telnet), 25 (SMTP), 37 (Time), 53 (DNS) e 80 (HTTP). O resultado da captura exibirá o IP de origem, o IP de destino e, se disponível, o conteúdo do pacote (payload).

UDP Insecure Scan: Semelhante à opção anterior, esta funcionalidade foca na captura de pacotes UDP nas mesmas portas. Embora o UDP seja um protocolo sem conexão, a inspeção de seu tráfego pode revelar informações úteis.

Look for specific IP: Esta é a opção mais flexível. Ela permite que você crie seu próprio filtro de captura com base em um protocolo e um endereço IP específicos. Por exemplo:
Para monitorar todo o tráfego TCP de um endereço específico, digite: tcp and host 192.168.1.1
Para capturar apenas pacotes ICMP (pacotes de ping) de um host específico, digite: icmp and host 10.0.0.5

Sair: Encerra o programa de forma segura.




⚠️ Considerações Importantes

Permissões: A captura de pacotes de rede é uma operação de baixo nível que requer privilégios de superusuário. Se o programa não funcionar, verifique se você o executou com as permissões corretas.
Finalidade: O UNSEC é uma ferramenta educacional. Utilize-a de forma responsável e apenas em redes onde você tem permissão explícita para monitorar o tráfego. O uso indevido pode ser ilegal e antiético.
