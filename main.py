#from PIL import Image,ImageTk
import PIL.Image
import PIL.ImageTk
import tkinter as tk
from tkinter import *
import joblib
import inputScript
from tkinter import messagebox
from Decision_Tree import d
from n_b import n

from RandomForest import r_f
from SupportVectorMachine import svmm

def training():

    def dt():
        d()
        messagebox.showinfo("Result", "Training Finished")

    def n_b():
        n()
        messagebox.showinfo("Result", "Training Finished")

    def rn_fr():
        r_f()
        messagebox.showinfo("Result", "Training Finished")

    def sm():
        svmm()
        messagebox.showinfo("Result", "Training Finished")           
        

    
    window2 = Toplevel()
    window2.geometry('700x500')
    fp = open("traing.jpg","rb")
    image = PIL.Image.open(fp)
    image=image.resize((700,500))
    photo_image=PIL.ImageTk.PhotoImage(image)
    label=Label(window2,image=photo_image)
    label.place(x=0,y=0)

    lb1 = Label(window2, text="Training Algorithum",font=('algerian',20,'bold'),justify='center',fg="BLUE")
    lb1.place(x=150, y=50)


    btn1 = Button(window2, text="Decision Tree", width=15, height=1,fg="black",font=('algerian',15,'bold'),bg="SKYBLUE",justify='center',command=dt)
    btn1.place(x=60, y=150)

    btn2 = Button(window2, text="S.V.M", width=15, height=1,fg="black",font=('algerian',15,'bold'),bg="SKYBLUE",justify='center',command=sm)
    btn2.place(x=420, y=150)

    btn3 = Button(window2, text="Random Forest", width=15, height=1,fg="black",font=('algerian',15,'bold'),bg="SKYBLUE",justify='center',command=rn_fr)
    btn3.place(x=60, y=380)

    btn4 = Button(window2, text="Naive Bayes", width=15, height=1,fg="black",font=('algerian',15,'bold'),bg="SKYBLUE",justify='center',command=n_b)
    btn4.place(x=420, y=380)

    
    window9.mainloop()

#-----------------------------------------------------------------
parameters = ["url_having_ip","url_length","url_short","having_at_symbol","doubleSlash",
                  "prefix_suffix",
                        "sub_domain","SSLfinal_State", "domain_registration", "favicon", "port",
                        "https_token","request_url", "url_of_anchor", "Links_in_tags",
                        "sfh", "email_submit",  "abnormal_url",
                        "redirect","on_mouseover","rightClick","popup","iframe",
                        "age_of_domain","dns","web_traffic","page_rank","google_index",
                        "links_pointing","statistical"]

def check_url():

    def resu():
        results = {}
        #window1.destroy()
        url=urls.get()

        classifier = joblib.load('final_models/rf_final.pkl')
        checkprediction = inputScript.main(url)
        for i in range(len(parameters)):
            if(checkprediction[0][i] == 1 or checkprediction[0][i] == 0):
                print(parameters[i] + " : ", end = " ")
                if(checkprediction[0][i] == 1):
                    print("Phishing")
                    results[parameters[i]] = "Phishing"
                else:
                    print("Suspicious")
                    results[parameters[i]] = "Suspicious"
        prediction = classifier.predict(checkprediction)
        print("Phishing: 1 || Suspicious: 0 || Legitimate: -1")
        print(str(prediction))
        if(str(prediction)=='[-1]'):
            messagebox.showinfo("Result", "This looks a safe URL")
            messagebox.showinfo("Reasons we think so", str(results))
        else:
            messagebox.showwarning("Result", "There is a high probability that this URL is Unsafe" )
            messagebox.showinfo("Reasons we think so", str(results))
        
        
    window9.destroy()
    window1 = Tk()
    window1.geometry('700x500')
    fp = open("url.jpg","rb")
    image = PIL.Image.open(fp)
    image=image.resize((700,500))
    photo_image=PIL.ImageTk.PhotoImage(image)
    label=Label(window1,image=photo_image)
    label.place(x=0,y=0)

    lb1 = Label(window1, text="Enter Your URL here",font=('Times',15),justify='center',fg="BLUE")
    lb1.place(x=100, y=150)
    
    urls=Entry(window1,width=35,font=("bold",15),highlightthickness=2)
    urls.place(x=100,y= 200)

    btn1 = Button(window1, text="URL CHECK", width=15, height=1,fg="black",font=('algerian',12,'bold'),bg="pink",justify='center',command=resu)
    btn1.place(x=500, y=200)
    window1.mainloop()

#-------------------------------------------------------------------

    
window9 = Tk()
window9.geometry('700x500')
fp = open("home.jpg","rb")
image = PIL.Image.open(fp)
image=image.resize((700,500))
photo_image=PIL.ImageTk.PhotoImage(image)
label=Label(window9,image=photo_image)
label.place(x=0,y=0)

lb1 = Label(window9, text="PHISHING WEBSITE SYSTEM",font=('algerian',20,'bold'),justify='center',fg="BLUE")
lb1.place(x=100, y=70)



btn1 = Button(window9, text="train", width=15, height=1,fg="black",font=('algerian',20,'bold'),bg="SKYBLUE",justify='center',command=training)
btn1.place(x=250, y=150)

btn1 = Button(window9, text="Click URL CHECK", width=15, height=1,fg="black",font=('algerian',20,'bold'),bg="SKYBLUE",justify='center',command=check_url)
btn1.place(x=250, y=300)




window9.mainloop()
