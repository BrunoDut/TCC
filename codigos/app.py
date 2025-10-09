import threading
import queue
import Captura as cap
import filtros
import shutil
import time
import os


fila = queue.Queue()
alert = queue.Queue()
detection = queue.Queue()

model_mult= r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\model_ML\modelo_RF_cicids_Multi.pkl'
model_bin = r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\model_ML\modelo_RF_cicids_binario.pkl'




def blocos_Pkts(interface,minute,fila,alert,stop_event):
    alert.put(f'Start Interface {interface} com o tempo: {minute} minutos')
    while not stop_event.is_set():
        dia = cap.time_format()
        minute = int(minute)
        cap.captura(interface,minute,dia)
        fila.put(dia)
        alert.put(f'\n#### captura do pacote realizada {dia} ####')

    
    fila.put(None)
    alert.put('ENCERRADO a Captura')

import queue, time

def translate_csv(fila, alert, detection):
    """
    Thread de tradução que processa os pacotes da fila.
    """
    while True:
        try:
            # Espera até 1s por um item da fila
            dia = fila.get(timeout=1)

            # Se o item for None → sinal de encerramento
            if dia is None:
                break  

            # Caminho do arquivo pcap
            arquivoPcap = rf"C:\Users\bruno\Documents\TCC\AplicacaoTCC\pcap\teste_Features_{dia}.pcap"

            # Executa extração de features
            filtros.executarCICFlow(arquivoPcap=arquivoPcap)

            # Classificação ML
            res = ML_classifier(dia=dia, model_mult=model_mult, model_bin=model_bin)

            # Se não houver pacotes capturados, envia alerta e continua para próximo item
            if res is None or res.empty:
                alert.put(f" Nenhum pacote capturado para o bloco {dia}. Execute a captura antes de classificar. ")
                fila.task_done()
                continue  # não quebra a thread, pega próximo item

            ataques = res[(res['isAttack'] != "BENIGN") | (res['type_attack'] != "BENIGN")]

            for index, df in ataques.iterrows():
                detection.put(
                f"Ip source: {df['Src IP']} "
                f"Ip Dest: {df['Dst IP']} " 
                f"Protocol: {df['Protocol']} "
                f"Destination Port: {df['Destination Port']} " 
                f"IsAtack: {df['isAttack']} "
                f"TypeAtack: {df['type_attack']} "
            )
            time.sleep(1)

            fila.task_done()
            alert.put(f"\n### Classificação do bloco de pacotes {dia} realizada ###")

        except queue.Empty:
            # Se a fila está vazia, espera e tenta de novo
            time.sleep(0.5)
            continue

        except Exception as e:
            # Captura qualquer outro erro para não quebrar a thread
            alert.put(f"Erro durante classificação do bloco {dia}: {e}")
            fila.task_done()
            continue

    print("### Processo de tradução finalizado ###")
    alert.put("ENCERRADO A CLASSIFICAÇÃO \n ###Processo Terminado####")


def ML_classifier(dia, model_mult, model_bin,):
        arquivo_Csv = rf'C:\Users\bruno\Documents\TCC\AplicacaoTCC\csv\teste_Features_{dia}.pcap_Flow.csv'
        df_mult, df_bin, df_src_dst = filtros.filter_atributes(arquivo=arquivo_Csv)
        if df_mult.empty or df_bin.empty:
            return None
        else:
            predict_mult, predict_bin = filtros.classification_ML(df_mult,df_bin,model_mult,model_bin)
            return filtros.save_Classifier(df=df_src_dst,predict_mult = predict_mult,predict_bin=predict_bin, nome_arquivo= f'Predict_{cap.time_format()}_')
        
        
def is_atack(df):
    atack = df[df['isAttack'] != 'BENIGN']
    return atack

def init_capture():
    captura_threads = threading.Thread(target = blocos_Pkts ,args = (fila,alert),daemon=True)
    traducao_threads = threading.Thread(target = translate_csv ,args=(fila,alert))

    captura_threads.start()
    traducao_threads.start()

    captura_threads.join()
    traducao_threads.join()
    print("###Processo terminado###")
    
def clear_queue(fila):
    while not fila.empty():
        try:
            fila.get_nowait()
        except fila.empty():
            break
    
def delete(Path,alert):
    for diretorio in Path:
        if os.path.exists(diretorio):
            alert.put(f'Apagando o conteudo do Diretorio {diretorio}')
            shutil.rmtree(diretorio)
    
        os.mkdir(diretorio)
        alert.put(f'{diretorio} Pasta Zerada')