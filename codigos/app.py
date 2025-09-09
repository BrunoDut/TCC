import threading
import queue
import Captura as cap
import filtros
import shutil
import os


fila = queue.Queue()
alert = queue.Queue()

model_mult= r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\model_ML\modelo_RF_cicids_Multi.pkl'
model_bin = r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\model_ML\modelo_RF_cicids_binario.pkl'




def blocos_Pkts(fila,alert,stop_event):
    alert.put('Start')
    while not stop_event.is_set():
        dia = cap.time_format() 
        cap.captura('Wi-Fi',3,dia)
        fila.put(dia)
        alert.put(f'\n#### captura do pacote realizada {dia} ####')

    
    fila.put(None)
    alert.put('ENCERRADO a Captura')

def translate_csv(fila, alert, stop_event):
    """
    Thread de tradução que processa os pacotes da fila.
    """
    while True:
        try:
            # Tenta pegar um item da fila sem bloquear indefinidamente
            dia = fila.get(timeout=1)
        except queue.Empty:
            if stop_event.is_set():
                break
            else:
                continue # Continua tentando se o sinal não foi setado

        if dia is None:
            # Se o sinal de parada for None, retorna para a fila para outros consumidores
            fila.put(None)
            break
            
        arquivoPcap = rf"C:\Users\bruno\Documents\TCC\AplicacaoTCC\pcap\teste_Features_{dia}.pcap"
        filtros.executarCICFlow(arquivoPcap=arquivoPcap)
        ML_classifier(dia = dia, model_mult=model_mult, model_bin=model_bin)
        
        fila.task_done()
        
        alert.put(f'\n### Classificação do bloco de pacotes {dia} realizada ###')

    print('### Processo de tradução finalizado ###')
    alert.put('ENCERRADO A CLASSIFICAÇÃO \n ###Processo Terminado####')

def ML_classifier(dia, model_mult, model_bin,):
        arquivo_Csv = rf'C:\Users\bruno\Documents\TCC\AplicacaoTCC\csv\teste_Features_{dia}.pcap_Flow.csv'
        df_mult, df_bin, df_src_dst = filtros.filter_atributes(arquivo=arquivo_Csv)
        predict_mult, predict_bin = filtros.classification_ML(df_mult,df_bin,model_mult,model_bin)
        filtros.save_Classifier(df=df_src_dst,predict_mult = predict_mult,predict_bin=predict_bin, nome_arquivo= f'Predict_{cap.time_format()}_')
        
           
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