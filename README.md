UNSEC

Unsec Tool

📚 Documentação: UNSEC - Monitor de Tráfego HTTP com Scapy

Este script Python, nomeado UNSEC, oferece funcionalidades básicas para monitorar o tráfego HTTP (porta 80) utilizando a poderosa biblioteca Scapy. Ele permite capturar e exibir informações de pacotes de duas maneiras distintas: um resumo básico ou detalhes completos do pacote.

⚙️ Pré-requisitos

Para executar o UNSEC, você precisará ter o Python e a biblioteca Scapy instalados em seu sistema.

    Instalação do Scapy:
    Você pode instalar o Scapy usando pip:
    

    pip install scapy

🚀 Como Usar o UNSEC

    Primeiro, você precisará clonar o repositório do UNSEC para sua máquina local usando git clone. Abra seu terminal ou prompt de comando e execute:
    
    git clone https://github.com/lifealil/UNSEC.git

Entre no diretório UNSEC/:

    cd UNSEC

Após clonar o repositório e navegar para a pasta do projeto, instale a biblioteca Scapy usando pip (caso ainda não tenha instalado):

    pip install scapy

Execute o Script:
Abra um terminal ou prompt de comando e execute o script Python:


    python unsec.py

    Menu Principal do UNSEC:
    Ao iniciar o script, você será apresentado a um menu principal com as seguintes opções:

    ------------------------------------------------------------
    Select an option: 

    -- 1.HTTP Monitor BASIC:
    -- 2.HTTP Monitor Packets:
    -- exit

    > 

        1. HTTP Monitor BASIC: Selecionar esta opção iniciará a captura de pacotes HTTP na porta 80 e exibirá um resumo conciso de cada pacote capturado. Ideal para uma visão geral rápida do tráfego.

        2. HTTP Monitor Packets: Esta opção também captura pacotes HTTP, mas exibe as informações completas e detalhadas de cada pacote, mostrando todos os campos e camadas. Útil para uma análise aprofundada.

        exit: Digite exit para sair do programa.

    Iniciando o Monitoramento com UNSEC:
    Após selecionar uma opção (1 ou 2), o serviço será iniciado e o monitoramento do tráfego HTTP começará. Você verá os resumos ou detalhes dos pacotes serem exibidos no terminal à medida que forem capturados.

    ---------> Starting Service...
    ------------------------------------------------------------
    ---------> Service Started!

    Monitoring HTTP TRAFFIC:

    Re-execução:
    Por padrão, o UNSEC captura até 150 pacotes. Após atingir esse limite (ou se você interromper a captura manualmente, por exemplo, com Ctrl+C), o menu principal será exibido novamente, permitindo que você escolha outra opção ou saia do programa.

📝 Funções Internas do UNSEC

    http_monitorBasic(packet):
    Esta função é um callback chamada para cada pacote capturado. Ela itera sobre os pacotes e imprime um resumo (p.summary()) de cada um, fornecendo informações básicas como os endereços IP de origem e destino, portas e o protocolo.

    http_monitorPacket(packet):
    Similar à função anterior, esta também é um callback para cada pacote. No entanto, ela utiliza p.show() para exibir todos os detalhes de cada pacote, incluindo todas as camadas e campos, o que é extremamente útil para depuração e análise detalhada.

    mainMenu():
    Esta é a função principal que gerencia a interface do usuário. Ela exibe o menu, solicita a seleção do usuário e, com base na escolha, invoca a função sniff() do Scapy. A função sniff() é configurada para:

        filter="tcp port 80": Capturar apenas pacotes TCP na porta 80 (tráfego HTTP).

        prn: Especifica a função de callback a ser executada para cada pacote capturado (http_monitorBasic ou http_monitorPacket).

        count=150: Define o número máximo de pacotes a serem capturados antes de retornar ao menu principal.

        iface="": (Observação: Atualmente, este parâmetro está vazio, o que pode fazer o Scapy tentar detectar automaticamente a interface ou não funcionar corretamente em alguns ambientes. Para ambientes de produção, é recomendável especificar a interface de rede, por exemplo, iface="eth0" ou iface="Wi-Fi").

⚠️ Considerações Importantes para o UNSEC

    Permissões: Em sistemas Linux/macOS, pode ser necessário executar o script com privilégios de superusuário (e.g., sudo python unsec_monitor.py) para que o Scapy possa capturar pacotes de rede.

    Interface de Rede (iface): O parâmetro iface="" na função sniff significa que o Scapy tentará detectar automaticamente a interface de rede. Em alguns sistemas, isso pode não funcionar como esperado. Se você tiver problemas, tente especificar o nome da sua interface de rede (por exemplo, iface="eth0", iface="wlan0", iface="en0", ou o nome da sua interface Wi-Fi). Você pode listar as interfaces disponíveis no seu sistema usando comandos como ip a (Linux) ou ipconfig (Windows) ou ifconfig (macOS).

    Contagem de Pacotes: O count=150 limita a captura a 150 pacotes. Para capturar indefinidamente, você pode remover o parâmetro count. No entanto, isso exigiria que você interrompesse o script manualmente (por exemplo, Ctrl+C).

    Segurança: O UNSEC é uma ferramenta de monitoramento. Use-o de forma responsável e apenas em redes onde você tem permissão para monitorar o tráfego.

---------------------------------------------------------------------------------------------------------------------------------


UNSEC

Unsec Tool

📚 Documentation: UNSEC - HTTP Traffic Monitor with Scapy

This Python script, named UNSEC, offers basic functionalities to monitor HTTP traffic (port 80) using the powerful Scapy library. It allows you to capture and display packet information in two distinct ways: a basic summary or complete packet details.

⚙️ Prerequisites

To run UNSEC, you'll need Python and the Scapy library installed on your system.

    Scapy Installation:
    You can install Scapy using pip:
    
    pip install scapy

🚀 How to Use UNSEC

    First, you'll need to clone the UNSEC repository to your local machine using git clone. Open your terminal or command prompt and execute:
    
    git clone https://github.com/lifealil/UNSEC.git

Enter the UNSEC/ directory:

    cd UNSEC

After cloning the repository and navigating to the project folder, install the Scapy library using pip (if you haven't already):

    pip install scapy

Execute the Script:
Open your terminal or command prompt and run the Python script:


    python unsec.py

    UNSEC Main Menu:
    Upon starting the script, you'll be presented with a main menu offering the following options:

    ------------------------------------------------------------
    Select an option: 

    -- 1.HTTP Monitor BASIC:
    -- 2.HTTP Monitor Packets:
    -- exit

    > 

        1. HTTP Monitor BASIC: Selecting this option will start capturing HTTP packets on port 80 and display a concise summary of each captured packet. This is ideal for a quick overview of traffic.

        2. HTTP Monitor Packets: This option also captures HTTP packets, but it displays complete and detailed information for each packet, showing all fields and layers. This is useful for in-depth analysis.

        exit: Type exit to quit the program.

    Starting Monitoring with UNSEC:
    After selecting an option (1 or 2), the service will start, and HTTP traffic monitoring will begin. You'll see packet summaries or details displayed in the terminal as they are captured.

    ---------> Starting Service...
    ------------------------------------------------------------
    ---------> Service Started!

    Monitoring HTTP TRAFFIC:

    Re-execution:
    By default, UNSEC captures up to 150 packets. After reaching this limit (or if you manually stop the capture, for example, with Ctrl+C), the main menu will reappear, allowing you to choose another option or exit the program.

📝 Internal Functions of UNSEC

    http_monitorBasic(packet):
    This function is a callback called for each captured packet. It iterates over the packets and prints a summary (p.summary()) for each, providing basic information such as source and destination IP addresses, ports, and the protocol.

    http_monitorPacket(packet):
    Similar to the previous function, this is also a callback for each packet. However, it uses p.show() to display all the details of each packet, including all layers and fields, which is extremely useful for debugging and detailed analysis.

    mainMenu():
    This is the main function that manages the user interface. It displays the menu, prompts for user selection, and based on the choice, invokes Scapy's sniff() function. The sniff() function is configured for:

        filter="tcp port 80": To capture only TCP packets on port 80 (HTTP traffic).

        prn: Specifies the callback function to be executed for each captured packet (http_monitorBasic or http_monitorPacket).

        count=150: Defines the maximum number of packets to be captured before returning to the main menu.

        iface="": (Note: Currently, this parameter is empty, which might cause Scapy to attempt automatic interface detection or not work correctly in some environments. For production environments, it's recommended to specify the network interface, e.g., iface="eth0" or iface="Wi-Fi").

⚠️ Important Considerations for UNSEC

    Permissions: On Linux/macOS systems, you might need to run the script with superuser privileges (e.g., sudo python unsec_monitor.py) for Scapy to be able to capture network packets.

    Network Interface (iface): The iface="" parameter in the sniff function means Scapy will try to automatically detect the network interface. In some systems, this might not work as expected. If you encounter issues, try specifying your network interface name (e.g., iface="eth0", iface="wlan0", iface="en0", or your Wi-Fi interface name). You can list available interfaces on your system using commands like ip a (Linux) or ipconfig (Windows) or ifconfig (macOS).

    Packet Count: count=150 limits the capture to 150 packets. To capture indefinitely, you can remove the count parameter. However, this would require you to manually stop the script (e.g., Ctrl+C).

    Security: UNSEC is a monitoring tool. Use it responsibly and only on networks where you have permission to monitor traffic.
