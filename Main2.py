from tkinter import *
from tkinter import ttk
from functools import partial
from tkinter import filedialog
import os,sys
from KeyChain import KeyChain

pm=KeyChain()

def validateLogin(masterPassword):
	
	return

def openFileAuth():
    pm.fileAuth =  filedialog.askopenfilename(initialdir = sys.path,title = "Select file",filetypes = (("txt","*.txt"),("all files","*.*")))
    return
def openFilePass():
    pm.filePass =  filedialog.askopenfilename(initialdir = sys.path,title = "Select file",filetypes = (("txt","*.txt"),("all files","*.*")))
    return
def openFileSha():
    pm.fileSha =  filedialog.askopenfilename(initialdir = sys.path,title = "Select file",filetypes = (("txt","*.txt"),("all files","*.*")))
    return

def load(masterPassword):

    pm.masterPassword=masterPassword.get()
    pm.load(pm.masterPassword,pm.filePass,pm.fileSha,pm.fileAuth)
    return





main_screen = Tk()   # create a GUI window 
main_screen.geometry("400x600") # set the configuration of GUI window 
main_screen.title("KeyChain") # set the title of GUI window
tab_control = ttk.Notebook(main_screen)

tab1 = ttk.Frame(tab_control)
tab2 = ttk.Frame(tab_control)

  

# create a Form label 
Label(tab1,text="KeyChain Passwords", bg="red", width="300", height="2", font=("Calibri", 13)).pack() 
Label(tab1,text="").pack() 

Label(tab2,text="KeyChain Passwords", bg="red", width="300", height="2", font=("Calibri", 13)).pack() 
Label(tab2,text="").pack() 

# create Login Button 

masterPassword = StringVar()
passFileName = StringVar()
sha256FileName = StringVar()
authFileName = StringVar()
load2 = partial(load, masterPassword)

Label(tab2, text="Master Password",).pack()
Entry(tab2, textvariable=masterPassword,show="*").pack()


Button(tab2,text="Cargar Contraseñas", height="2", width="30",command=openFilePass).pack() 
Label(tab2,text=str(pm.filePass)).pack() 
Button(tab2,text="Cargar Sha256", height="2", width="30",command=openFileSha).pack() 
Label(tab2,text=pm.fileSha).pack() 
Button(tab2,text="Cargar Auténticación", height="2", width="30",command=openFileAuth).pack() 
Label(tab2,text=pm.fileAuth).pack() 
Button(tab2,text="Cargar Llavero", height="2", width="30",command=load2).pack() 



# create a register button
masterPassword = StringVar()
# validateLogin2 = partial(validateLogin, masterPassword)
Label(tab1, text="Master Password",).pack()
Entry(tab1, textvariable=masterPassword,show="*").pack()
# Button(tab1,text="Crear Llavero", height="2", width="30",command=validateLogin2).pack()
Label(tab1,text="").pack() 
 
tab_control.add(tab1, text='Crear Llavero ')
tab_control.add(tab2, text='Cargar Llavero')
tab_control.pack(expand=1, fill='both')

main_screen.mainloop() # start the GUI