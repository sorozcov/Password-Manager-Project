# ---------------------------------------------------------------------------- #
#                      Universidad del Valle de Guatemala                      #
#                      Cifrado de información 2020 2                           #
#                      Grupo 7                                                 #
#                      Main.py                                                 #
# ---------------------------------------------------------------------------- #
from tkinter import *
from tkinter import ttk
from functools import partial
from tkinter import filedialog
import os,sys
from KeyChain import KeyChain

pm=KeyChain()



def InitScreen(screen):
    #Screen config
    screen()

def StartScreen():
    
    #Functions    
    def openFilePass():
        pm.filePass =  filedialog.askopenfilename(initialdir = sys.path,title = "Select file",filetypes = (("txt","*.txt"),("all files","*.*")))
        passFileName.set(pm.filePass.split("/").pop())
        return

    def openFileSha():
        pm.fileSha =  filedialog.askopenfilename(initialdir = sys.path,title = "Select file",filetypes = (("txt","*.txt"),("all files","*.*")))
        sha256FileName.set(pm.fileSha.split("/").pop())
        return

    def openFileAuth():
        pm.fileAuth =  filedialog.askopenfilename(initialdir = sys.path,title = "Select file",filetypes = (("txt","*.txt"),("all files","*.*")))
        authFileName.set(pm.fileAuth.split("/").pop())
        return

    def init():
        response = pm.init(newMasterPassword.get())
        if(response[0]):
            errorTab1.set('')
            tab_control.destroy()
            pm.resetFiles()
            InitScreen(MainScreen)
            
        else:
            errorTab1.set(response[1])
        return

    def load():
        if(pm.filePass == None or pm.fileSha == None or pm.fileAuth == None):
            errorTab2.set('No se han cargado todos los archivos')
            return
        else:
            errorTab2.set('')   
        response = pm.load(masterPassword.get(),pm.filePass,pm.fileSha,pm.fileAuth)
        if(response[0]):
            errorTab2.set('')
            tab_control.destroy()
            pm.resetFiles()
            InitScreen(MainScreen)
        else:
            errorTab2.set(response[1])
        return

    # Tabs init
    tab_control = ttk.Notebook(app)
    tab1 = ttk.Frame(tab_control)
    tab2 = ttk.Frame(tab_control)
    tab_control.add(tab1, text='Crear Llavero ')
    tab_control.add(tab2, text='Cargar Llavero')
    tab_control.pack(expand=1, fill='both')


    # Tab1 elements
    newMasterPassword = StringVar()
    errorTab1 = StringVar()

    Label(tab1,text="KeyChain Passwords", bg='#00aae4', fg='white', width="300", height="2", font=("Calibri", 13)).pack() 
    Label(tab1,text="").pack() 
    Label(tab1, text="Contraseña Maestra",).pack()
    Entry(tab1, textvariable=newMasterPassword,show="*").pack()
    Label(tab1,text="").pack() 
    Button(tab1,text="Crear Llavero", height="2", width="30",command=init, bg='blue', fg='white').pack() 
    Label(tab1,textvariable=errorTab1, fg="red").pack() 
    
    # Tab2 elements
    masterPassword = StringVar()
    passFileName = StringVar()
    sha256FileName = StringVar()
    authFileName = StringVar()
    errorTab2 = StringVar()

    Label(tab2,text="KeyChain Passwords", bg='#00aae4', fg='white', width="300", height="2", font=("Calibri", 13)).pack() 
    Label(tab2,text="").pack() 
    Label(tab2, text="Contraseña Maestra",).pack()
    Entry(tab2, textvariable=masterPassword,show="*").pack()
    Label(tab2,text="").pack() 
    Button(tab2,text="Cargar archivo de contraseñas", height="2", width="30",command=openFilePass).pack() 
    Label(tab2,textvariable=passFileName).pack() 
    Button(tab2,text="Cargar archivo de Sha256", height="2", width="30",command=openFileSha).pack() 
    Label(tab2,textvariable=sha256FileName).pack() 
    Button(tab2,text="Cargar archivo de autenticación", height="2", width="30",command=openFileAuth).pack() 
    Label(tab2,textvariable=authFileName).pack() 
    Button(tab2,text="Cargar Llavero", height="2", width="30",command=load, bg='blue', fg='white').pack() 
    Label(tab2,textvariable=errorTab2, fg="red").pack() 
    


def MainScreen():
    
    #Functions    
    def openFilePass():
        pm.filePass =  filedialog.askopenfilename(initialdir = sys.path,title = "Select file",filetypes = (("txt","*.txt"),("all files","*.*")))
        passFileName.set(pm.filePass.split("/").pop())
        return

    def openFileSha():
        pm.fileSha =  filedialog.askopenfilename(initialdir = sys.path,title = "Select file",filetypes = (("txt","*.txt"),("all files","*.*")))
        sha256FileName.set(pm.fileSha.split("/").pop())
        return

    def openFileAuth():
        pm.fileAuth =  filedialog.askopenfilename(initialdir = sys.path,title = "Select file",filetypes = (("txt","*.txt"),("all files","*.*")))
        authFileName.set(pm.fileAuth.split("/").pop())
        return

    def getPassword():
        response = pm.get(applicationToSearch.get())
        if(response[0]):
            errorTab1.set('')
            passwordOfApplication.set('Contraseña: ' + response[1])
        else:
            errorTab1.set(response[1])
            passwordOfApplication.set('Contraseña: ')
        return 

    def setPassword():
        response = pm.set(newApplication.get(), newPassword.get())
        if(response[0]):
            infoTab2.set(response[1])
            labelNewApplication.config(fg="green")
        else:
            infoTab2.set(response[1])
            labelNewApplication.config(fg="red")
        return   

    def removePassword():
        response = pm.remove(applicationToRemove.get())
        if(response[0]):
            infoTab3.set(response[1])
            labelApplicationToRemove.config(fg="green")
        else:
            infoTab3.set(response[1])
            labelApplicationToRemove.config(fg="red")
        return   

    def saveKeyChain():
        if(pm.filePass == None or pm.fileSha == None or pm.fileAuth == None):
            errorTab4.set('No se han cargado todos los archivos')
            return
        pm.saveKeyChain(pm.filePass,pm.fileSha,pm.fileAuth)
        tab_control.destroy()
        pm.reset()
        pm.resetFiles()
        InitScreen(StartScreen)


        
    
    # Tabs init
    tab_control = ttk.Notebook(app)
    tab1 = ttk.Frame(tab_control)
    tab2 = ttk.Frame(tab_control)
    tab3 = ttk.Frame(tab_control)
    tab4 = ttk.Frame(tab_control)
    tab_control.add(tab1, text='Consultar Contraseñas')
    tab_control.add(tab2, text='Agregar Contraseña')
    tab_control.add(tab3, text='Eliminar Contraseña')
    tab_control.add(tab4, text='Guardar y Cerrar Sesión')
    tab_control.pack(expand=1, fill='both')


    # Tab1 elements
    applicationToSearch = StringVar()
    passwordOfApplication = StringVar()
    passwordOfApplication.set('Contraseña: ')
    errorTab1 = StringVar()

    Label(tab1,text="Consultar Contraseñas", bg='#00aae4', fg='white', width="300", height="2", font=("Calibri", 13)).pack() 
    Label(tab1,text="").pack() 
    Label(tab1, text="Aplicación de la contraseña a consultar").pack()
    Entry(tab1, textvariable=applicationToSearch).pack()
    Label(tab1,text="").pack() 
    Button(tab1,text="Buscar Contraseña", height="2", width="30",command=getPassword, bg='blue', fg='white').pack() 
    Label(tab1,textvariable=errorTab1, fg="red").pack()
    Label(tab1,text="").pack() 
    Label(tab1,text="").pack() 
    Label(tab1, textvariable=passwordOfApplication, bg='#00aae4', fg='white', width="40", height="2", borderwidth=2, relief="solid", font=("Calibri", 10)).pack()

    # Tab2 elements
    newApplication = StringVar()
    newPassword = StringVar()
    infoTab2 = StringVar()

    Label(tab2,text="Agregar Contraseña", bg='#00aae4', fg='white', width="300", height="2", font=("Calibri", 13)).pack() 
    Label(tab2,text="").pack()
    Label(tab2, text="Aplicación").pack()
    Label(tab2, text="(Si ingresas una que ya existe actualiza la contraseña)", font=("Calibri", 8)).pack()
    Entry(tab2, textvariable=newApplication).pack()
    Label(tab2,text="").pack() 
    Label(tab2, text="Contraseña").pack()
    Entry(tab2, textvariable=newPassword, show="*").pack()
    Label(tab2,text="").pack() 
    Button(tab2,text="Agregar Contraseña", height="2", width="30",command=setPassword, bg='blue', fg='white').pack() 
    labelNewApplication = Label(tab2,textvariable=infoTab2)
    labelNewApplication.pack()

    # Tab3 elements
    applicationToRemove = StringVar()
    infoTab3 = StringVar()

    Label(tab3,text="Eliminar Contraseña", bg='#00aae4', fg='white', width="300", height="2", font=("Calibri", 13)).pack() 
    Label(tab3,text="").pack()
    Label(tab3, text="Aplicación").pack()
    Entry(tab3, textvariable=applicationToRemove).pack()
    Label(tab3,text="").pack() 
    Button(tab3,text="Eliminar Contraseña", height="2", width="30",command=removePassword, bg='blue', fg='white').pack() 
    labelApplicationToRemove = Label(tab3,textvariable=infoTab3)
    labelApplicationToRemove.pack()

    # Tab4 elements
    passFileName = StringVar()
    sha256FileName = StringVar()
    authFileName = StringVar()
    errorTab4 = StringVar()

    Label(tab4,text="Guardar y Cerrar Sesión", bg='#00aae4', fg='white', width="300", height="2", font=("Calibri", 13)).pack() 
    Label(tab4,text="").pack() 
    Button(tab4,text="Cargar archivo de contraseñas", height="2", width="30",command=openFilePass).pack() 
    Label(tab4,textvariable=passFileName).pack() 
    Button(tab4,text="Cargar archivo de Sha256", height="2", width="30",command=openFileSha).pack() 
    Label(tab4,textvariable=sha256FileName).pack() 
    Button(tab4,text="Cargar archivo de autenticación", height="2", width="30",command=openFileAuth).pack() 
    Label(tab4,textvariable=authFileName).pack() 
    Button(tab4,text="Cerrar Sesión", height="2", width="30",command=saveKeyChain, bg='blue', fg='white').pack() 
    Label(tab4,textvariable=errorTab4, fg="red").pack() 


#Create the app
app = Tk()   # create a GUI window 
app.geometry("600x400") # set the configuration of GUI window 
app.title("KeyChain") # set the title of GUI window

app.iconbitmap('KeyChain.ico')
#Init the GUI
InitScreen(StartScreen)
#Start the GUI
app.mainloop() 

#pyinstaller.exe --onefile --icon=KeyChain.ico Main.py
#https://screenrec.com/share/LGcI9e7Hs8
