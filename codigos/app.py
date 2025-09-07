import threading
import queue
import time
import Captura as cap
import filtros


model_mult= r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\model_ML\modelo_RF_cicids_Multi.pkl'
model_bin = r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\model_ML\modelo_RF_cicids_binario.pkl'


def blocos_Pkts(fila):
    for i in range(0,5):
        cap.captura('Wi-Fi',5,i)
        fila.put(i+1)
        print(f'captura do pacote realizada {i+1}')

def translate_csv(fila):
    while(True):
        numero = fila.get()
        arquivoPcap = rf"C:\Users\bruno\Documents\TCC\AplicacaoTCC\pcap\teste_Features{int(numero)}.pcap" 
        filtros.executarCICFlow(arquivoPcap=arquivoPcap)
        ML_classifier(numero=numero,model_mult=model_mult,model_bin=model_bin)
        fila.task_done()
        print(f'Filtragem realizada!!')


def ML_classifier(numero, model_mult, model_bin):
        arquivo_Csv = rf'C:\Users\bruno\Documents\TCC\AplicacaoTCC\resultados\teste_Features{int(numero)}.pcap_Flow.csv'
        df_mult, df_bin = filtros.filter_atributes(arquivo=arquivo_Csv)
        predict_mult, predict_bin = filtros.classification_ML(df_mult,df_bin,model_mult,model_bin)
        print("###Resultados: ###")
        print("###ML Multiclasse: ###")
        print(predict_mult)
        print("###ML Binario: ###")
        print(predict_bin)
        
           
fila = queue.Queue()
captura_threads = threading.Thread(target = blocos_Pkts ,args = (fila,))
traducao_threads = threading.Thread(target = translate_csv ,args=(fila,))

captura_threads.start()
traducao_threads.start()

captura_threads.join()
traducao_threads.join()

print("Processo terminado")