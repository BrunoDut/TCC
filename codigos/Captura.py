import subprocess as sb
from datetime import datetime as dt 

def time_format():
    horario = dt.now()
    return horario.strftime("%d_%m_%Y-%H_%M_%S")

def Executavel(comando):
    TSHARK_EXECUTAVEL = r"C:\Program Files\Wireshark\tshark.exe"
    comando_final = [TSHARK_EXECUTAVEL] + comando.split()
    
    print(f'[*] Executando: {" ".join(comando_final)}')
    
    try:
        resultado = sb.run(
            comando_final,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        return resultado.stdout
    except FileNotFoundError:
        print("⚠️ Executável tshark não encontrado.")
        return None
    except sb.CalledProcessError as e:
        print(f"[ERRO] O TShark retornou:\n{e.stderr}")
        return None


def captura(interface, tempo_min,dia):
        print(f' Capturando o pacote: {dia}')
        arquivo_saida = rf"C:\Users\bruno\Documents\TCC\AplicacaoTCC\pcap\teste_Features_{time_format()}.pcap"
        comando = f"-i {interface} -a duration:{tempo_min*10} -w {arquivo_saida}"
        Executavel(comando)
