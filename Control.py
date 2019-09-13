# Defines a ControlNumber object that stores data pertaining to
# a specific Control Number (e.g: AC-1) in the RMF document.
# The object contains data necessary to linking to numbers in a STIG.
class ControlNumber:

    cciLinked = None
    stigLinked = None
    stigFileName = ""

    def __init__(self):
        self.rmfNumber = ""             # Number of the control in NIST-80053 (e.g: AC-1)
        self.rmfTitle = ""              # Title of control, (e.g: THREAT AWARENESS PROGRAM), possible way of finding headers
        self.rmfPriority = ""           # Priority (e.g: P1)
        self.rmfFamily = ""             # Family (e.g: ACCESS CONTROL)
        self.rmfImpact = ""             # Highest impact (LOW, MODERATE, HIGH)
        self.rmfStatement = ""          # Poorly named description
        self.rmfParents = []            # A list of parent numbers (currently not functional)

        self.cciNumbers = []            # A list of linked CCI numbers
        self.stigNumbers = []           # A list of linked STIG Numbers. Key = STIG V number, value is the description.

# * This method translates any number found in the CCI List XML document to a form that can be cross referenced by the program.
# * The method is necessary because there are discrepencies in the syntax of RMF numbers in the CCI List and RMF documents.
# * PLEASE NOTE: With every revision change of the NIST-800-53 document, the translation technique may require changes!

def doCCITranslation(input):
    transChars = list(input)                                                # Converts the input string to a list that can be edited
    timesDeleted = 0
    i = 0

    while i < len(input):
        ch = input[i]

        if ch >= 'a' and ch <= 'z':                                         # Checks if the character is lower case
            if input[i-1] == ' ':                                           # Only if the character before the lower case is a space, replace with a dash
                transChars[i-1] = '-'
            elif ch == '.':                                                 # Otherwise, if the character is a period replace with a dash
                transChars[i] = '-'
            elif ch >= '0' and ch <= '9' and input[i-1] == ' ':             # Otherwise, if the character is a number and the previous character is a space, replace the space with a dash
                transChars[i-1] = '-'
            elif ch == '(' and input[i-1] == ' ' and input[i-2] == ')':     # Otherwise, if a space is sandwiched in between two parentheses, delete it
                del transChars[i - timesDeleted - 1]
                timesDeleted += 1                                           # Increments a count of how many times this procedure was done. Has to be factored in, because if there is another occurence, it has to replace slot (i - 1 - k)s
            i += 1
        translatedStr = "".join(transChars)
        return translatedStr


# * This method translates any number found in the RMF XML document to a form that can be cross referenced by the program.
# * The method is necessary because there are discrepencies in the syntax of RMF numbers in the CCI List and RMF documents.
# * PLEASE NOTE: With every revision change of the NIST-800-53 document, the translation technique may require changes!

def doRMFTranslation(input):

        transChars = list(input)                                # Converts the input string to a list that can be edited
        i = 0
        timesExpanded = 0
        while i < len(input):
            k = i + timesExpanded                               # Adjusted index, used when dealing with the new character list. It takes into account slot expansion
            ch = input[i]
            if ch == '.':                                       # If the character is a period, replace it with a dash, or if it's the last character delete it
                if k == len(transChars)-1:
                    del transChars[k]
                else:
                    transChars[k] = '-'
            if ch >= 'a' and ch <= 'z':                         # If the character is a lowercase letter preceeded by a number (AC-10a), insert a dash in between the number and lowercase letter (AC-10-a)
                if input[i-1] >= '0' and input[i-1] <= '9':
                    transChars.insert(k,'-')
                    timesExpanded += 1                          # Acts as a count of how many times the list is expanded. Needs to be accounted for when editing the list for a future character
            i += 1
        translatedStr = "".join(transChars)
        return translatedStr