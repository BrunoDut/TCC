import subprocess as sb
import pandas as pd
import numpy as np
import joblib as job



    
MAPEAMENTO_COLUNAS = {
    "Dst Port": "Destination Port",
    "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
    "Label": "Label"
}

filter_mult = [
    'Destination Port', 'Init_Win_bytes_backward', 'Subflow Fwd Bytes',
    'Total Length of Fwd Packets', 'Init_Win_bytes_forward',
    'Fwd Packet Length Max', 'Average Packet Size', 'Packet Length Mean',
    'Subflow Bwd Bytes', 'Fwd Header Length', 'Fwd Packet Length Mean',
    'Subflow Fwd Packets', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Avg Fwd Segment Size',
    'Packet Length Variance', 'Bwd Header Length', 'Avg Bwd Segment Size',
    'Flow IAT Max', 'Flow Duration', 'Fwd IAT Max', 'Subflow Bwd Packets',
    'min_seg_size_forward', 'Flow IAT Std', 'Total Length of Bwd Packets',
    'Fwd Packet Length Std', 'Total Backward Packets', 'Packet Length Std',
    'act_data_pkt_fwd', 'Fwd IAT Total', 'Fwd IAT Std', 'Bwd Packets/s',
    'Max Packet Length', 'Bwd Packet Length Max', 'Fwd IAT Min',
    'Flow Bytes/s'
]

filter_bin = [
       'Destination Port', 'Average Packet Size', 'Init_Win_bytes_backward',
       'Fwd Packet Length Min', 'Max Packet Length', 'Bwd Packet Length Min',
       'Init_Win_bytes_forward', 'Fwd Packet Length Max',
       'Bwd Packet Length Std', 'Packet Length Std',
       'Total Length of Fwd Packets', 'Avg Bwd Segment Size',
       'Packet Length Variance', 'Packet Length Mean',
       'Bwd Packet Length Mean', 'Bwd Packet Length Max', 'Min Packet Length',
       'Avg Fwd Segment Size', 'Total Length of Bwd Packets',
       'Fwd Header Length', 'Fwd Packet Length Mean', 'Subflow Fwd Bytes',
       'Flow Packets/s'
]



def executarCICFlow(arquivoPcap):
    # Caminho para a pasta que contém o script .bat
    diretorio_bin = r"C:\Users\bruno\Documents\TCC\AplicacaoTCC\CICFlowMeter-4.0\bin"
    
    script_bat = "cfm.bat"
    
    arquivo_pcap = rf"{arquivoPcap}"
    
    pasta_resultados = r"C:\Users\bruno\Documents\TCC\AplicacaoTCC\resultados"

    comando = [
        script_bat,
        arquivo_pcap,
        pasta_resultados
    ]
    
    print(f"[*] Executando no diretório: {diretorio_bin}")
    print(f"[*] Comando: {' '.join(comando)}")
    
    try:
        resultado = sb.run(
            comando,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8"',
            cwd=diretorio_bin,
            shell=True 
        )
        print("[+] Execução concluída com sucesso!")
        return resultado.stdout
    
    except FileNotFoundError:
        print("[ERRO] Comando não encontrado. Verifique o caminho em 'diretorio_bin' e o nome do script.")
        return None
    except sb.CalledProcessError as e:
        print("[ERRO] O script retornou um erro.")
        print("Saída Padrão (stdout):", e.stdout)
        print("Saída de Erro (stderr):", e.stderr)
        return None
    
def filter_atributes(arquivo):
    df = pd.read_csv(arquivo) # CRIA O DATAFRAME
    df.columns = df.columns.str.strip()
    df = df.rename(columns=MAPEAMENTO_COLUNAS)
    
    df_filter_mult = df[filter_mult] #filtragem do modelo multiclasse
    df_filter_bin = df[filter_bin]
    return df_filter_mult, df_filter_bin


def classification_ML(df_mult, df_bin, model_mult, model_bin):
    modelo_mult = job.load(model_mult)
    modelo_bin = job.load(model_bin)
    
    
    coluna_treino_mult = modelo_mult.feature_names_in_
    coluna_treino_bin = modelo_bin.feature_names_in_
    
    
    df_mult = df_mult.reindex(columns = coluna_treino_mult, fill_value = 0)
    df_mult = df_mult.replace([np.inf, -np.inf], np.nan)
    df_mult = df_mult.fillna(0)
    
    df_bin = df_bin.reindex(columns = coluna_treino_bin, fill_value = 0)
    df_bin = df_bin.replace([np.inf, -np.inf], np.nan)
    df_bin = df_bin.fillna(0)
    
    
    predict_mult = modelo_mult.predict(df_mult)
    predict_bin = modelo_bin.predict(df_bin)
    
    return  predict_mult, predict_bin

#model1 = r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\Include\model_ML\modelo_RF_cicids_Multi.pkl'
#model2 = r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\Include\model_ML\modelo_RF_cicids_binario.pkl'

#dataframe_mult, dataframe_bin = filter_atributes(r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\resultados\teste_Features1.pcap_Flow.csv') 

#resultado1, resultado2= classification_ML(df1=dataframe_mult, df2=dataframe_bin , model_mult=model1, model_bin=model2)

#print("###Resultados: ###")
#("###ML Multiclasse: ###")
#print(resultado1)
#print("###ML Binario: ###")
#print(resultado2)


#df = pd.read_csv(r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\resultados\teste_Features1.pcap_Flow.csv')
#print(df.columns)
#cols_originais = df.columns.tolist()
#df = df.rename(columns=MAPEAMENTO_COLUNAS)
#print(df.columns)

#nao_mapeadas = [c for c in cols_originais if c not in MAPEAMENTO_COLUNAS.keys()]
#nao_convertidas = [c for c in filter_mult + filter_bin if c not in MAPEAMENTO_COLUNAS.values() and c not in cols_originais]

#print("Colunas originais sem mapeamento:", nao_mapeadas)
#print("Colunas esperadas que não aparecem:", nao_convertidas)