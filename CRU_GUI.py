import Control
import CRU
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from lxml import etree


def launchGUI():
    
    # GUI Variables & Objects---------------------------------

    rmfList = CRU.initializeControlNumbersList()
    CRU.linkSTIGNumbers(rmfList,)

    SampleNum = rmfList[0]
    mapsDict = {SampleNum.stigFileName:rmfList}     # A dictionary of maps generated, so you can import multiple stigs and switch between them
    del SampleNum

    stigDict = CRU.generateVulnNumbers()

    # GUI Constants------------------------------------------

    MARGIN_SIZE = 30
    FONT_SIZE = 12
    HEADER_FONT_SIZE = 14
    LIST_FONT_SIZE = 10
    INDENT_AMOUNT = 30

    BACKGROUND_COLOR = "lightgrey"
    SECONDARY_COLOR = "#F5F5F5"
    INNER_COLOR = "white"
    TEXT_COLOR = "BLACK"

    # Root window----------------------------------------
    root = Tk()
    root.configure(bg=BACKGROUND_COLOR)
    root.title("RMF Cross Reference Utility")
    root.geometry("1000x600+100+100")

    root.columnconfigure(0, weight=1)
    root.columnconfigure(1, weight=1)

    root.rowconfigure(1, weight=1)
    root.rowconfigure(3, weight=2)

    # Info text box--------------------------------------
    infoLabel = Label(root, text="Extracted Information", bg = SECONDARY_COLOR, fg=TEXT_COLOR, font="Helvetica 10")
    infoLabel.grid(row=2, column=0, columnspan=2, sticky=W+E, padx=MARGIN_SIZE)
    infoLabel.config(anchor=CENTER)

    infoTextBox = Text(root, state=DISABLED, font="Helvetica " + str(FONT_SIZE), wrap=WORD, height=30, bg=INNER_COLOR, fg=TEXT_COLOR)
    infoTextBox.grid(row=3,  column=0, columnspan=2, sticky=N+S+E+W, padx=MARGIN_SIZE, pady = (0, MARGIN_SIZE))
    infoTextBox.tag_configure("header", font="Helvetica " + str(HEADER_FONT_SIZE) + " bold", justify="center")
    infoTextBox.tag_configure("highlight", font="Helvetica " + str(FONT_SIZE) + " bold")
    infoTextBox.tag_configure("indented", lmargin1=str(INDENT_AMOUNT), lmargin2 =str(INDENT_AMOUNT))


    def rmfNumberSelection(event):

        infoTextBox.config(state=NORMAL)            # Enable text box to be edited
        widget = event.widget                       # Get listbox widget

        if widget.curselection():                       # Check if something is actually selected
            infoTextBox.delete("1.0",END)               # Delete anything in the box

            if "V-" not in widget.get(0):               # If it is from the RMF numbers list
                selectionNumbers = widget.curselection()    # Get the index numbers for the current selection
                selectionNum = selectionNumbers[0]          # Get the single index number for the current selection
                rmfNumber = str(widget.get(selectionNum))   # Get the string at the index given before
                rmfNumber = rmfNumber.strip()               # Trim any whitespace from the list
                currentSelection = rmfNumber

                print(rmfNumber)
                
                infoTextBox.insert(END, "\n")
                infoTextBox.insert(END, "   Control Number " + rmfNumber + "\n\n", "header")

                for ControlNum in rmfList:
                    if ControlNum.rmfNumber == rmfNumber:
                        infoTextBox.insert(END, "   Number: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfNumber + "\n\n")
                        infoTextBox.insert(END, "   Family: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfFamily + "\n\n")
                        infoTextBox.insert(END, "   Title: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfTitle + "\n\n")
                        infoTextBox.insert(END, "   Priority: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfPriority + "\n\n")
                        infoTextBox.insert(END, "   Impact: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfImpact + "\n\n")
                        infoTextBox.insert(END, "   Defintion: \n", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfStatement + "\n\n", "indented")
                        
                        if ControlNum.stigNumbers:
                            infoTextBox.insert(END, "   Linked STIG Information ", "header")
                        
                        for vNumber in ControlNum.stigNumbers:
                            VulnNumber = stigDict[vNumber]

                            infoTextBox.insert(END, "\n\n   Number: ", "highlight")
                            infoTextBox.insert(END, VulnNumber.vNumber + "\n\n", "indented")
                            infoTextBox.insert(END, "   Title: ", "highlight")
                            infoTextBox.insert(END, VulnNumber.title + "\n\n", "indented")
                            infoTextBox.insert(END, "   Description: \n", "highlight")
                            infoTextBox.insert(END, VulnNumber.description + "\n\n", "indented")
                            infoTextBox.insert(END, "   Fix: \n", "highlight")
                            infoTextBox.insert(END,VulnNumber.fix + "\n\n", "indented")
                            infoTextBox.insert(END, "   Check: \n", "highlight")
                            infoTextBox.insert(END, VulnNumber.check + "\n\n", "indented")

            else:
                selectionNumbers = widget.curselection()    # Get the index numbers for the current selection
                selectionNum = selectionNumbers[0]          # Get the single index number for the current selection
                vNumber = str(widget.get(selectionNum))     # Get the string at the index given before
                vNumber = vNumber.strip()                   # Trim any whitespace from the 
                currentSelection = vNumber
                VulnNumber = stigDict[vNumber]

                print(vNumber)

                infoTextBox.insert(END, "\n")
                infoTextBox.insert(END, "   Vulnerability Number " + vNumber, "header")

                infoTextBox.insert(END, "\n\n   Number: ", "highlight")
                infoTextBox.insert(END, VulnNumber.vNumber + "\n\n", "indented")
                infoTextBox.insert(END, "   Title: ", "highlight")
                infoTextBox.insert(END, VulnNumber.title + "\n\n", "indented")
                infoTextBox.insert(END, "   Description: \n", "highlight")
                infoTextBox.insert(END, VulnNumber.description + "\n\n", "indented")
                infoTextBox.insert(END, "   Fix: \n", "highlight")
                infoTextBox.insert(END,VulnNumber.fix + "\n\n", "indented")
                infoTextBox.insert(END, "   Check: \n", "highlight")
                infoTextBox.insert(END, VulnNumber.check + "\n\n", "indented")

                for ControlNum in rmfList:
                    if vNumber in ControlNum.stigNumbers:
                        infoTextBox.insert(END, "   Linked RMF Information ", "header")

                        infoTextBox.insert(END, "\n\n   Number: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfNumber + "\n\n")
                        infoTextBox.insert(END, "   Family: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfFamily + "\n\n")
                        infoTextBox.insert(END, "   Title: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfTitle + "\n\n")
                        infoTextBox.insert(END, "   Priority: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfPriority + "\n\n")
                        infoTextBox.insert(END, "   Impact: ", "highlight") 
                        infoTextBox.insert(END, ControlNum.rmfImpact + "\n\n")



        infoTextBox.config(state=DISABLED)

    # Top Labels--------------------------------------

    # Frames so we can hold buttons as well as the label:
    rmfLabelFrm = Frame(root)
    rmfLabelFrm.grid(row=0, column=0, padx=(MARGIN_SIZE,0), sticky=E+W+S+N)
    rmfLabelFrm.columnconfigure(0, weight=1)

    stigLabelFrm = Frame(root)
    stigLabelFrm.grid(row=0, column=1, padx=(0,MARGIN_SIZE), sticky= E+W+S+N)
    stigLabelFrm.columnconfigure(0, weight=1)

    # Add labels:
    rmfListLabel = Label(rmfLabelFrm, text="NIST 800-53 Revision 4", justify=CENTER, bg=SECONDARY_COLOR, fg=TEXT_COLOR, font="Helvetica 10")
    rmfListLabel.grid(row=0, column=0, sticky = E+W)
    rmfListLabel.config(anchor=CENTER)

    stigListLabel = Label(stigLabelFrm, text="Windows 10 STIG", justify=CENTER, bg=SECONDARY_COLOR, fg=TEXT_COLOR, font="Helvetica 10")
    stigListLabel.grid(row=0, column=0, sticky= E+W)      
    stigListLabel.config(anchor=CENTER)    
        
    currentSel = StringVar(stigLabelFrm)
    currentSel.set('')
    #currentSel.trace("w", switchStig())
    stigDropDown = OptionMenu(stigLabelFrm, currentSel, *mapsDict)
    #stigDropDown.grid(row=0, column=1, sticky=E)


    # RMF number and STIG number listboxes---------------

    listsFrame = Frame(root, relief=FLAT)
    listsFrame.grid(row=1, column=0, columnspan=2, sticky=N+E+S+W, padx=MARGIN_SIZE)

    listsFrame.columnconfigure(0, weight=1)
    listsFrame.columnconfigure(1, weight=1)

    # Listboxes

    rmfFrame = Frame(listsFrame)                                    # Frames are necessary for scrollbars
    rmfFrame.grid(row=1, column=0, sticky=N+E+S+W)

    stigFrame = Frame(listsFrame)
    stigFrame.grid(row=1, column=1, sticky=N+S+E+W)

    rmfFrame.columnconfigure(0, weight=1)
    rmfFrame.columnconfigure(1, weight=1)
    stigFrame.columnconfigure(0, weight=1)
    stigFrame.columnconfigure(1, weight=1)


    rmfNumbersList = Listbox(rmfFrame, height=23, width=40, font="Helvetica " + str(LIST_FONT_SIZE), bg=INNER_COLOR, fg=TEXT_COLOR, borderwidth=1, highlightthickness=0)
    rmfNumbersList.grid(row=0, column=0, columnspan=2, sticky=N+S+E+W)
    rmfNumbersList.bind('<<ListboxSelect>>', rmfNumberSelection)        # Binds the selection event to point to method above

    stigNumbersList = Listbox(stigFrame, height=23, width=40, font="Helvetica " + str(LIST_FONT_SIZE), bg=INNER_COLOR, fg=TEXT_COLOR, borderwidth=1, highlightthickness=0)
    stigNumbersList.grid(row=0, column=0, columnspan=2, sticky=N+S+E+W)
    stigNumbersList.bind('<<ListboxSelect>>', rmfNumberSelection)

    # Scroll bars
    rmfScrollbar = Scrollbar(rmfFrame, orient="vertical", bg=BACKGROUND_COLOR)
    rmfScrollbar.grid(row=0, column=1, sticky=N+S+E)
    rmfNumbersList.config(yscrollcommand=rmfScrollbar.set)
    rmfScrollbar.config(command=rmfNumbersList.yview)

    stigScrollbar = Scrollbar(stigFrame, orient="vertical")
    stigScrollbar.grid(row=0, column=1, sticky=N+S+E)
    stigNumbersList.config(yscrollcommand=stigScrollbar.set)
    stigScrollbar.config(command=stigNumbersList.yview)
    # Fill RMF Numbers List-------------------------------

    def fillLists(numList):

        stigNumbersList.delete(0, END)
        rmfNumbersList.delete(0, END)

        for rmfNum in numList:
            rmfNumbersList.insert(END, "    " + rmfNum.rmfNumber)

            for stigNum in rmfNum.stigNumbers:
                stigNumbersList.insert(END, "    " + stigNum)

    # Menu bar--------------------------------------------

    menubar = Menu(root)

    # Import STIG file menu button command
    def importStig():
        # Open file dialog
        filePath = filedialog.askopenfilename(initialdir = "/", title = "Select STIG file", filetypes = (("xml files", "*.xml"), ("all files", ".*")))
        
        CRU.linkSTIGNumbers(rmfList, filePath)                  # Link stig numbers
        SampleNum = rmfList[0]

        stigDict.clear()                                        # Clear any stigs in stig dict
        stigDict.update(CRU.generateVulnNumbers(filePath))      # 

        fillLists(rmfList)

        stigListLabel.config(text=SampleNum.stigFileName)

        print(filePath)
        del SampleNum
        del filePath

    def refresh():
        rmfListLabel.update_idletasks()
    
    # Quit GUI command
    def closeGui():
        root.destroy()
        sys.exit()

    # File Menu---------------------------------------
    def enableDarkMode():
        BACKGROUND_COLOR = "#212121"
        SECONDARY_COLOR = "#303030"
        INNER_COLOR = "#424242"
        TEXT_COLOR = "WHITE"

        infoLabel.config(bg=SECONDARY_COLOR, fg=TEXT_COLOR, font="Helvetica 10 bold")
        infoTextBox.config(bg=INNER_COLOR, fg=TEXT_COLOR)
        rmfListLabel.config(bg=SECONDARY_COLOR, fg=TEXT_COLOR, font="Helvetica 10 bold")
        stigListLabel.config(bg=SECONDARY_COLOR, fg=TEXT_COLOR, font="Helvetica 10 bold")
        rmfNumbersList.config(bg=INNER_COLOR, fg=TEXT_COLOR)
        stigNumbersList.config(bg=INNER_COLOR, fg=TEXT_COLOR)
        root.config(bg=BACKGROUND_COLOR)



    def enableLightMode():
        BACKGROUND_COLOR = "lightgrey"
        SECONDARY_COLOR = "#F5F5F5"
        INNER_COLOR = "white"
        TEXT_COLOR = "BLACK"

        infoLabel.config(bg=SECONDARY_COLOR, fg=TEXT_COLOR, font="Helvetica 10")
        infoTextBox.config(bg=INNER_COLOR, fg=TEXT_COLOR)
        rmfListLabel.config(bg=SECONDARY_COLOR, fg=TEXT_COLOR, font="Helvetica 10")
        stigListLabel.config(bg=SECONDARY_COLOR, fg=TEXT_COLOR, font="Helvetica 10")
        rmfNumbersList.config(bg=INNER_COLOR, fg=TEXT_COLOR)
        stigNumbersList.config(bg=INNER_COLOR, fg=TEXT_COLOR)
        root.config(bg=BACKGROUND_COLOR)

    filemenu = Menu(menubar, tearoff=0)
    filemenu.add_command(label="Import STIG from file", command = importStig)

    filemenu.add_separator()
    filemenu.add_command(label = "Exit", command = closeGui)
    menubar.add_cascade(label="File", menu=filemenu)                # Add the file menu to the menubar

    # View Menu
    viewmenu = Menu(menubar, tearoff=0)
    viewmenu.add_command(label="Light Mode", command = enableLightMode)
    viewmenu.add_command(label="Dark Mode", command = enableDarkMode)
    menubar.add_cascade(label="View", menu=viewmenu)

    root.config(menu=menubar)                                       # Set the GUI's menu 

    fillLists(rmfList)
    root.mainloop()