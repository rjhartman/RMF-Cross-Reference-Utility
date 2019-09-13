#	+-------------------------------------------------------------------+
#	| Security Control Correlation Tool						            |   
#	| Ryan Hartman & Jonathon Green                                     |
#   |                                                                   |
#   | 2016 Research Project with Rowan College at Burlington County and |
#   | Lockheed Martin.                                                  |
#   |                                                                   |
#   | Links NIST 800-53 Rev. 4 Risk Management Framework to any STIG XML|
#   | file and displays it inside of a GUI.								|
#	+-------------------------------------------------------------------+

# Version 1.0.1
# Recent additions:
# - Fully functional GUI
# - Control numbers are now objects that make querying much faster and easier

import Control
import CRU_GUI
import VulnerabilityNumber
from lxml import etree

CURRENT_REVISION = "4"           # Current NIST-80053 Revision

# Below are various element trees. Essentially they are the entire XML document built into element trees
# It is structured so we can access all elements and build a map with objects

rmfDocument = etree.parse("src\\docs\\80053.xml")
cciList = etree.parse("src\\docs\\CCIList.xml")
rmfRoot = rmfDocument.getroot()
cciRoot = cciList.getroot()
def cleanContent(contentStr):

        charList = list(contentStr)

        i = 0
        insideTag = None
        endOfTag = None

        while i < len(charList):
            char = charList[i]

            if char == "<":
                insideTag = True
            if char == ">":
                endOfTag = True
            
            if insideTag:
                del charList[i]
                i -= 1

            if endOfTag:
                insideTag = None
                endOfTag = None
        
            i += 1
        
        return "".join(charList)

# Translate a STIG's file name into a readable form

def translateStigName(name):
    charList = list(name)

    i = 0
    # Replace every underscore with a space
    while i < len(charList):
        if charList[i] == "_":
            charList[i] = " "
        i += 1
        
    return "".join(charList)

# Return a dictionary of Vulnerability objects that are generated from a certain STIG file
def generateVulnNumbers(stigFilePath="STIGs\\win10.xml"):
    stigDocument = etree.parse(stigFilePath)
    stigRoot = stigDocument.getroot()
    stigName = ""

    vulnNumberDict = {}

    # Get the name of the stig:
    for element in stigRoot.iter("{http://checklists.nist.gov/xccdf/1.1}Benchmark"):
        stigAttrib = element.attrib
        stigName = translateStigName(stigAttrib["id"])

    for element in stigRoot.iter("{http://checklists.nist.gov/xccdf/1.1}Group"):
        VulnNumber = VulnerabilityNumber.Vulnerability()
        VulnNumber.stigFileName = stigName

        stigAttrib = element.attrib
        VulnNumber.vNumber = stigAttrib["id"]

        for child in element.getchildren():
            if child.tag == "{http://checklists.nist.gov/xccdf/1.1}Rule":
                for grandchild in child.getchildren():
                    if grandchild.tag == "{http://checklists.nist.gov/xccdf/1.1}title":
                        VulnNumber.title = grandchild.text

                    if grandchild.tag == "{http://checklists.nist.gov/xccdf/1.1}description":
                        VulnNumber.description = cleanContent(grandchild.text)

                    if grandchild.tag == "{http://checklists.nist.gov/xccdf/1.1}fixtext":
                        VulnNumber.fix = cleanContent(grandchild.text)

                    if grandchild.tag == "{http://checklists.nist.gov/xccdf/1.1}check":
                        for content in grandchild.getchildren():
                            if content.tag == "{http://checklists.nist.gov/xccdf/1.1}check-content":
                                VulnNumber.check = cleanContent(content.text)
        
        if VulnNumber is not None:

            vulnNumberDict.update({VulnNumber.vNumber:VulnNumber})
    
    return vulnNumberDict





# Link STIG numbers to a list of ControlNumber objects
def linkSTIGNumbers(numList, stigFilePath="STIGs\\win10.xml"):
    
    SampleNum = numList[0]
    stigName = ""
    
    if not SampleNum.cciLinked:             # See if the numbers are already linked to a cci
        linkCCINumbers(numList)             # If not, link them

    for ControlNum in numList:              # Clear any currently stored vnumbers
        ControlNum.stigNumbers.clear()

    # Get element trees
    stigDocument = etree.parse(stigFilePath)
    stigRoot = stigDocument.getroot()

    for element in stigRoot.iter("{http://checklists.nist.gov/xccdf/1.1}Benchmark"):
        stigAttrib = element.attrib
        stigName = translateStigName(stigAttrib["id"])

    for element in stigRoot.iter("{http://checklists.nist.gov/xccdf/1.1}Group"):
        stigAttrib = element.attrib
        vNumber = stigAttrib["id"]

        for child in element.iter("{http://checklists.nist.gov/xccdf/1.1}ident"):
            cciNumberQuery = child.text

            for ControlNum in numList:
                if cciNumberQuery in ControlNum.cciNumbers:
                    ControlNum.stigNumbers.append(vNumber)
    
    SampleNum.stigFileName = translateStigName(stigName)


# Link CCI numbers to a list of ControlNumber objects
def linkCCINumbers(numList):

    SampleNum = numList[0]
    SampleNum.cciLinked = True
    
    for element in cciRoot.iter("{http://iase.disa.mil/cci}cci_item"):
        
        cciNumber = element.attrib["id"]

        for child in element:
            if child.tag == "{http://iase.disa.mil/cci}references":
                for grandChild in child:
                    if grandChild.attrib["version"] == CURRENT_REVISION:
                        rmfNum = Control.doCCITranslation(grandChild.attrib["index"])

                        for ControlNum in numList:
                            #DEBUGGING: print("Searching for: ", rmfNum, " Found:", ControlNum.rmfNumber, " Boolean: ", (rmfNum == ControlNum.rmfNumber))
                            if ControlNum.rmfNumber == rmfNum:
                                ControlNum.cciNumbers.append(cciNumber)


def initializeControlNumbersList():

    controlNumbers = []

    for element in rmfRoot.iter("{http://scap.nist.gov/schema/sp800-53/feed/2.0}control", "{http://scap.nist.gov/schema/sp800-53/2.0}statement"):
        
        ControlNumber = generateControlNumber(element)
        
        if ControlNumber is not None:
            controlNumbers.append(ControlNumber)

    return controlNumbers


# Checks if an element is a control number.
# If it is, it will fill a control number object with the contents of the found number
# TO-DO: Retrieve the random descriptions hidden in statement tags, and fill a list of parents of each control
def generateControlNumber(E):
    ControlNum = Control.ControlNumber()
    childList = E.getchildren()                                                 # Get a list of element's children
    isControlNumber = False                                                     # Flag to know if the element being scanned is a number
    
    for child in childList:                                                     # Scan each child tag in the element...

        # Check for all satisfying tags and fill information:

        if child.tag == "{http://scap.nist.gov/schema/sp800-53/2.0}family":
            ControlNum.rmfFamily = child.text
            isControlNumber = True

        if child.tag == "{http://scap.nist.gov/schema/sp800-53/2.0}number":
            ControlNum.rmfNumber = Control.doRMFTranslation(child.text)
            isControlNumber = True

        if child.tag == "{http://scap.nist.gov/schema/sp800-53/2.0}title":
            ControlNum.rmfTitle = child.text
            isControlNumber = True

        if child.tag == "{http://scap.nist.gov/schema/sp800-53/2.0}priority":
            ControlNum.rmfPriority = child.text
            isControlNumber = True

        if child.tag == "{http://scap.nist.gov/schema/sp800-53/2.0}baseline-impact":
            ControlNum.rmfImpact = child.text
            isControlNumber = True

        if child.tag == "{http://scap.nist.gov/schema/sp800-53/2.0}description":
            ControlNum.rmfStatement = child.text

    if isControlNumber:         # If this is an actual number, return the object
        return ControlNum
    else:                       # If not, return None to be handled outside.
        return None

# Below function is for debugging
# It will output all tags found in NIST-80053
def outputRMFTags(number=0):
    i = 1
    for element in rmfRoot.iter():
        if i <= number or number <= 0: 
            print(i, ": ", element.tag)
        i += 1

# Output all tags in the CCI file
def outputCCITags(number=0):
    i = 1
    for element in cciRoot.iter():
        if i <= number or number <= 0: 
            print(i, ": ", element.tag)
        i += 1

# Output all tags in the STIG file
def outputSTIGTags(number=0, stigFilePath="STIGs\\win10.xml"):

    stigDocument = etree.parse(stigFilePath)
    stigRoot = stigDocument.getroot()

    i = 1
    for element in stigRoot.iter():
        if i <= number or number <= 0: 
            print(i, ": ", element.tag)
        i += 1


CRU_GUI.launchGUI()