import subprocess as sb


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


def captura(interface, tempo_min,i):
        print(f' Capturando o pacote: {i+1}')
        arquivo_saida = rf"C:\Users\bruno\Documents\TCC\AplicacaoTCC\pcap\teste_Features{i+1}.pcap"
        comando = f"-i {interface} -a duration:{tempo_min*20} -w {arquivo_saida}"
        Executavel(comando)
