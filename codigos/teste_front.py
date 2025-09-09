import threading
import queue
import PySimpleGUI as sg
import app

fila = queue.Queue()
alert = queue.Queue()
stop_event = threading.Event()

pasta_a_Deletar = [
    r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\csv',
    r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\pcap',
    r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\resultados'
    ]

sg.theme("DarkBlue14")  # Deixa o visual mais moderno



layout = [
    [sg.Text("📡 Monitoramento de Rede", font=("Arial", 18, "bold"), justification="center", expand_x=True)],
    [sg.Button("▶ Capturar", size=(12,2), button_color=("white", "green")),
     sg.Button("🛑 Parar", size=(12,2), button_color=("white", "red")),
     sg.Button("Limpar Documentos",size=(12,2), button_color=("white", "purple"),font=('Arial',10))],
    [sg.Multiline("", key="-INFO-", size=(50,20), font=("Arial", 12), disabled=True, autoscroll=True),
     sg.Multiline("", key="-Respostas-", size=(100,20), font=("Arial", 12), disabled=True, autoscroll=True)],
    [sg.Button("Sair", size=(12,2), button_color=("white", "gray"))]
]

Logo = r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\Imagens\beecons v2.png'
window = sg.Window("App Redes - TCC", layout, size=(1300, 700), element_justification="left",icon = Logo)

def limpa_tela():
    window['-INFO-'].update('')

while True:
    event, values = window.read(timeout=100) 
        
    if event in (sg.WINDOW_CLOSED, "Sair"):
        if stop_event:
            break
        else:
            stop_event.set()
            break
        
        
    elif event == "▶ Capturar":
        app.clear_queue(alert)
        limpa_tela()
        stop_event.clear()
       
        captura_threads = threading.Thread(target = app.blocos_Pkts ,args = (fila,alert,stop_event),daemon=True)
        traducao_threads = threading.Thread(target = app.translate_csv ,args=(fila,alert,stop_event))
        
        
        captura_threads.start()
        traducao_threads.start()
        
        
        
    elif event == "🛑 Parar":
        stop_event.set()
    
    elif event == "Limpar Documentos":
        limpa_tela()
        app.clear_queue(alert)
        thread_limpeza = threading.Thread(target=app.delete, args=(pasta_a_Deletar, alert), daemon=True)
        thread_limpeza.start()
        alert.put('Iniciando limpeza dos diretórios...')
    try:
        dados = alert.get_nowait()
        window['-INFO-'].update(f'Status: {dados}\n', append=True)
    except queue.Empty:
        # A fila está vazia, continue o loop
        pass
    
    
window.close()
