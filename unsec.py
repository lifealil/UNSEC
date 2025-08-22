from scapy.all import sniff
from colorama import init, Fore, Back, Style
import time
import keyboard

# Inicializa a função do colorama.
init()

# Função para cancelar a execução de captura.
def wait_for_cancel():
    print(Fore.CYAN + "\nVocê tem 3 segundos para cancelar (Ctrl+C), antes que a captura comece.\n" + Style.RESET_ALL)
    try:
        time.sleep(3)
        return True
    except KeyboardInterrupt:
        print(Fore.RED + "\nCaptura cancelada pelo usuário." + Style.RESET_ALL)
        return False



# Função para scan de pacotes TCP inseguros.
def scan_tcp(num_pacotes):
    print(Fore.WHITE + Back.RED + "\nIniciando a captura TCP... \n" + Style.RESET_ALL)
    try:
        sniff(
            filter='tcp and (port 21 or port 23 or port 25 or port 37 or port 53 or port 80)',
            count=num_pacotes,
            prn=lambda x: x.sprintf(Fore.BLUE + "#IP DE ORIGEM:" + Fore.GREEN + "    | {IP:%IP.src%}" + Fore.RED + "\n#IP DE DESTINO:" + Fore.GREEN + "  | {IP:%IP.dst%}" + Fore.WHITE + "\n\nPAYLOAD:\n" + Fore.GREEN + "{Raw:%Raw.load%}\n" + Style.RESET_ALL)
        )
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "Captura TCP encerrada pelo usuário." + Style.RESET_ALL)



# Função para scan de pacotes UDP inseguros.
def scan_udp(num_pacotes):
    print(Fore.WHITE + Back.RED + "\nIniciando a captura UDP... \n" + Style.RESET_ALL)
    try:
        sniff(
            filter='udp and (port 21 or port 23 or port 25 or port 37 or port 53 or port 80)',
            count=num_pacotes,
            prn=lambda x: x.sprintf(Fore.BLUE + "#IP DE ORIGEM:" + Fore.GREEN + "   | {IP:%IP.src%}" + Fore.RED + "\n#IP DE DESTINO:" + Fore.GREEN + "  | {IP:%IP.dst%}" + Fore.WHITE + "\n\nPAYLOAD:\n" + Fore.GREEN + "{Raw:%Raw.load%}\n" + Style.RESET_ALL)
        )
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "Captura UDP encerrada pelo usuário." + Style.RESET_ALL)



# Função para scan de protocolos e ips especificos.
def look_ip(ip_search, num_pacotes):
    print(Fore.WHITE + Back.RED + "\nIniciando a busca por IP...\n" + Style.RESET_ALL)
    try:
        sniff(
            filter=ip_search,
            count=num_pacotes,
            prn=lambda x: x.sprintf(Fore.BLUE + "#IP DE ORIGEM:" + Fore.GREEN + "   | {IP:%IP.src%}" + Fore.RED + "\n#IP DE DESTINO:" + Fore.GREEN + "  | {IP:%IP.dst%}" + Fore.WHITE + "\n\nPAYLOAD:\n" + Fore.GREEN + "{Raw:%Raw.load%}\n" + Style.RESET_ALL)
        )
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "Captura encerrada pelo usuário." + Style.RESET_ALL)



# Menu principal.
def main_menu():
    while True:
        try:
            print(Fore.GREEN + "-"*120, "")

            print(Fore.RED + "       UUUUUUUU     UUUUUUUUNNNNNNNN        NNNNNNNN   SSSSSSSSSSSSSSS EEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCC     ")
            print(Fore.RED + "       U::::::U     U::::::UN:::::::N       N::::::N SS:::::::::::::::SE::::::::::::::::::::E    CCC::::::::::::C     ")
            print(Fore.RED + "       U::::::U     U::::::UN::::::::N      N::::::NS:::::SSSSSS::::::SE::::::::::::::::::::E  CC:::::::::::::::C     ")
            print(Fore.RED + "       UU:::::U     U:::::UUN:::::::::N     N::::::NS:::::S     SSSSSSSEE::::::EEEEEEEEE::::E C:::::CCCCCCCC::::C     ")
            print(Fore.RED + "        U:::::U     U:::::U N::::::::::N    N::::::NS:::::S              E:::::E       EEEEEEC:::::C       CCCCCC     ")
            print(Fore.RED + "        U:::::D     D:::::U N:::::::::::N   N::::::NS:::::S              E:::::E            C:::::C                   ")
            print(Fore.RED + "        U:::::D     D:::::U N:::::::N::::N  N::::::N S::::SSSS           E::::::EEEEEEEEEE  C:::::C                   ")
            print(Fore.RED + "        U:::::D     D:::::U N::::::N N::::N N::::::N  SS::::::SSSSS      E:::::::::::::::E  C:::::C                   ")
            print(Fore.RED + "        U:::::D     D:::::U N::::::N  N::::N:::::::N    SSS::::::::SS    E:::::::::::::::E  C:::::C                   ")
            print(Fore.RED + "        U:::::D     D:::::U N::::::N   N:::::::::::N       SSSSSS::::S   E::::::EEEEEEEEEE  C:::::C                   ")
            print(Fore.RED + "        U:::::D     D:::::U N::::::N    N::::::::::N            S:::::S  E:::::E            C:::::C                   ")
            print(Fore.RED + "        U::::::U   U::::::U N::::::N     N:::::::::N            S:::::S  E:::::E       EEEEEEC:::::C       CCCCCC     ")
            print(Fore.RED + "        U:::::::UUU:::::::U N::::::N      N:::::::NS:::::::SSSSSS:::::SE::::::EEEEEEEE:::::E C:::::CCCCCCCC::::C     ")
            print(Fore.RED + "         UU:::::::::::::UU  N::::::N       N:::::::NS::::::SSSSSS:::::SE::::::::::::::::::::E  CC:::::::::::::::C     ")
            print(Fore.RED + "           UU:::::::::UU    N::::::N        N::::::NS:::::::::::::::SS E::::::::::::::::::::E    CCC::::::::::::C     ")
            print(Fore.RED + "             UUUUUUUUU      NNNNNNNN         NNNNNNN SSSSSSSSSSSSSSS   EEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCC     ")
            print(Fore.GREEN + "-"*120, "\n\n")
            print(Fore.GREEN + "-"*54, "UNSEC MENU", "-"*54)

            print(Fore.YELLOW + "\n\n\n1. TCP Insecure Scan (Scan on ports: 21, 23, 25, 37, 53, 80)")
            print(Fore.YELLOW + "2. UDP Insecure Scan (Scan on ports: 21, 23, 25, 37, 53, 80)")
            print(Fore.YELLOW + "3. Look for specific IP")
            print(Fore.YELLOW + "4. Sair")
            print(Style.RESET_ALL)

            selection = input("Digite uma opção para seguir: \n> ")

            if selection == '4' or selection.lower() == 'exit':
                print(Fore.GREEN + "Encerrando o programa." + Style.RESET_ALL)
                break
            
            if selection == '1':
                try:
                    num_pacotes = int(input(Fore.CYAN + "\nInsira a quantidade de capturas a serem feitas: \n> " + Style.RESET_ALL))
                    if wait_for_cancel():
                        scan_tcp(num_pacotes)
                except ValueError:
                    print(Fore.RED + "Entrada inválida. Por favor, digite um número inteiro." + Style.RESET_ALL)
            elif selection == '2':
                try:
                    num_pacotes = int(input(Fore.CYAN + "\nInsira a quantidade de capturas a serem feitas: \n> " + Style.RESET_ALL))
                    if wait_for_cancel():
                        scan_udp(num_pacotes)
                except ValueError:
                    print(Fore.RED + "Entrada inválida. Por favor, digite um número inteiro." + Style.RESET_ALL)
            elif selection == '3': # Mudado para string '3'
                try:
                    ip_search = input(Fore.CYAN + "\nDigite o Protocolo e o host alvo: (Usage ex: tcp and host 10.0.0.0)\n> " + Style.RESET_ALL)
                    num_pacotes = int(input(Fore.CYAN + "\nInsira a quantidade de capturas a serem feitas: \n> " + Style.RESET_ALL))
                    if wait_for_cancel():
                        look_ip(ip_search, num_pacotes) # Passando os argumentos
                except ValueError:
                    print(Fore.RED + "Entrada inválida. Por favor, digite um número inteiro." + Style.RESET_ALL)
            else:
                print(Fore.RED + "Opção inválida." + Style.RESET_ALL)

        except Exception as e:
            print(Fore.RED + f"Ocorreu um erro: {e}. Certifique-se de que você tem privilégios de administrador." + Style.RESET_ALL)
            break

main_menu()
