import threading
import queue
import PySimpleGUI as sg
import app
import time

fila = queue.Queue()
alert = queue.Queue()
detection = queue.Queue()
stop_event = threading.Event()

pasta_a_Deletar = [
    r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\csv',
    r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\pcap',
    r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\resultados'
    ]

sg.theme("DarkBlue14")  # Deixa o visual mais moderno



layout = [
    [sg.Text("📡 Monitoramento de Rede", font=("Arial", 18, "bold"), justification="center", expand_x=True)],
    [sg.Text('Adicione o tempo para captura em minutos (já configurado para 1 minuto)'), sg.InputText(key='-Time-')],
    [sg.Text('Selecione Uma Interface'),sg.Combo(values=['Wi-Fi','Ethernet'],key = "-Interface-",readonly=True)],
    [sg.Button("▶ Iniciar Capturar", size=(12,2), button_color=("white", "green")),
     sg.Button("🛑 Parar", size=(12,2), button_color=("white", "red")),
     sg.Button("Limpar Documentos",size=(12,2), button_color=("white", "purple"),font=('Arial',10))],
    [sg.Multiline("", key="-INFO-", size=(50,20), font=("Arial", 12), disabled=True, autoscroll=True),
     sg.Multiline("", key="-Respostas-", size=(100,20), font=("Arial", 12), disabled=True, autoscroll=True)],
    [sg.Button("Sair", size=(12,2), button_color=("white", "gray"))]
    
]

Logo = r'C:\Users\bruno\Documents\TCC\AplicacaoTCC\Imagens\Icone.ico'
window = sg.Window("App Redes - TCC", layout, size=(1300, 700), element_justification="left",icon = Logo)

def limpa_tela():
    window['-INFO-'].update('')


def iniciar():
    app.clear_queue(alert)
    app.clear_queue(detection)
    limpa_tela()
    stop_event.clear()

    captura_threads = threading.Thread(
        target=app.blocos_Pkts, 
        args=(interface,tempo,fila, alert, stop_event), 
        daemon=True
    )
    traducao_threads = threading.Thread(
        target=app.translate_csv, 
        args=(fila, alert, detection),
        daemon=True
    )

    captura_threads.start()
    traducao_threads.start()

while True:
    event, values = window.read(timeout=100)

    if event in (sg.WINDOW_CLOSED, "Sair"):
        stop_event.set()
        break

    elif event == "▶ Iniciar Capturar":
        try:
            res = values['-Time-']
            interface = values['-Interface-']
            if res == '':
                tempo = 1
            else:
                tempo = int(res)
            if interface == '':
                interface = 'Wi-Fi'    
            else:
                interface
            if (tempo > 0):
                
                iniciar()
            else:
                sg.popup('O tempo tem que ser maior que zero')
        except ValueError:
            sg.popup('você digitou uma letra, por favor insirir um numero')
        except Exception as e:
            sg.popup('desculpe o ocorreu um erro na execução tentar denovo')
    elif event == "🛑 Parar":
        stop_event.set()
        

    elif event == "Limpar Documentos":
        limpa_tela()
        app.clear_queue(alert)
        app.clear_queue(detection)

        thread_limpeza = threading.Thread(
            target=app.delete, 
            args=(pasta_a_Deletar, alert), 
            daemon=True
        )
        thread_limpeza.start()
        alert.put('Iniciando limpeza dos diretórios...')

    # Verificar mensagens das filas
    try:
        dados = alert.get_nowait()
        window['-INFO-'].update(f'Status: {dados}\n', append=True)
    except queue.Empty:
        pass

    try:
        detections = detection.get_nowait()
        window['-Respostas-'].update(f'Return: {detections}\n', append=True)
    except queue.Empty:
        pass

window.close()
