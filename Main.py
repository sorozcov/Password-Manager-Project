from KeyChain import KeyChain

# pm=KeyChain()
# pm.load('password')
# print(pm.set('app1','holahola'))
# print(pm.set('app2','holakpex'))
# print(pm.passwords)

# pm.saveKeyChain("rep.txt","hash.txt","auth.txt")


pm=KeyChain()
pm.load('password',"rep.txt","hash.txt","auth.txt")
# print(pm.set('app1','holahola'))
# print(pm.set('app2','holakpex'))
print(pm.passwords)
print(pm.get('app1'))
print(pm.get('app2'))
#pm.saveKeyChain("rep.txt","hash.txt","auth.txt")

