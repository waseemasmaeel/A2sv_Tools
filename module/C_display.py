#===========================
#              Display option                  #

# تعريف المتغير العام
displayMode = 0

def showDisplay(string):
    global displayMode
    if displayMode == 0:
        print(string)
    else:
        pass

def setDisplay(mode):
    global displayMode
    displayMode = mode

#===========================
