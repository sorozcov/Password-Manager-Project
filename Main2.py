from tkinter import *
from tkinter import ttk
from functools import partial
from tkinter import filedialog
import os,sys
from KeyChain import KeyChain

pm=KeyChain()

def validateLogin(masterPassword):
	
	return


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
    pm.init(newMasterPassword.get())
    print(pm.passwords)
    return

def load():
    pm.load(masterPassword.get(),passFileName.get(),sha256FileName.get(),authFileName.get())
    print(pm.passwords)
    return




#Main Screen config
main_screen = Tk()   # create a GUI window 
main_screen.geometry("400x600") # set the configuration of GUI window 
main_screen.title("KeyChain") # set the title of GUI window
tab_control = ttk.Notebook(main_screen)
tab1 = ttk.Frame(tab_control)
tab2 = ttk.Frame(tab_control)


# Tab1 elements
newMasterPassword = StringVar()
initFunction = partial(init)

Label(tab1,text="KeyChain Passwords", bg="red", width="300", height="2", font=("Calibri", 13)).pack() 
Label(tab1,text="").pack() 
Label(tab1, text="Master Password",).pack()
Entry(tab1, textvariable=newMasterPassword,show="*").pack()
Label(tab1,text="").pack() 
Button(tab1,text="Crear Llavero", height="2", width="30",command=initFunction).pack() 
 
# Tab2 elements
masterPassword = StringVar()
passFileName = StringVar()
sha256FileName = StringVar()
authFileName = StringVar()
loadFunction = partial(load)

Label(tab2,text="KeyChain Passwords", bg="red", width="300", height="2", font=("Calibri", 13)).pack() 
Label(tab2,text="").pack() 
Label(tab2, text="Master Password",).pack()
Entry(tab2, textvariable=masterPassword,show="*").pack()
Label(tab2,text="").pack() 
Button(tab2,text="Cargar Contraseñas", height="2", width="30",command=openFilePass).pack() 
Label(tab2,textvariable=passFileName).pack() 
Button(tab2,text="Cargar Sha256", height="2", width="30",command=openFileSha).pack() 
Label(tab2,textvariable=sha256FileName).pack() 
Button(tab2,text="Cargar Auténticación", height="2", width="30",command=openFileAuth).pack() 
Label(tab2,textvariable=authFileName).pack() 
Button(tab2,text="Cargar Llavero", height="2", width="30",command=loadFunction).pack() 

#Tabs config
tab_control.add(tab1, text='Crear Llavero ')
tab_control.add(tab2, text='Cargar Llavero')
tab_control.pack(expand=1, fill='both')

#Start the GUI
main_screen.mainloop() 