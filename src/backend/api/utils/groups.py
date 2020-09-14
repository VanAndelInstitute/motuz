# based upon answer from
# https://stackoverflow.com/questions/9323834/python-how-to-get-group-ids-of-one-username-like-id-gn/49775683#49775683

#
# Zack Ramjan 2018-09-13
#
'''
groups module for python

get the groups for a given user, works with ldap/sssd/etc

'''
import grp, pwd, os
from ctypes import *
from ctypes.util import find_library
import logging

class groups():

    def __init__(self):
        pass

    def getGroups(self,username):

        libc = cdll.LoadLibrary(find_library('libc'))


        getgrouplist = libc.getgrouplist
        # 100 groups should be enought?
        ngroups = 100
        getgrouplist.argtypes = [c_char_p, c_uint, POINTER(c_uint * ngroups), POINTER(c_int)]
        getgrouplist.restype = c_int32

        GIDlist = (c_uint * ngroups)()
        nGIDlist = c_int(ngroups)
        groupsList = []
        try:
            user = pwd.getpwnam(username)

            ct = getgrouplist(user.pw_name, user.pw_gid, byref(GIDlist), byref(nGIDlist))

            # if 50 groups was not enought this will be -1, try again
            # luckily the last call put the correct number of groups in ngrouplist
            if ct < 0:
                getgrouplist.argtypes = [c_char_p, c_uint, POINTER(c_uint *int(nGIDlist.value)), POINTER(c_int)]
                GIDlist = (c_uint * int(nGIDlist.value))()
                ct = getgrouplist(bytes(user.pw_name, 'UTF-8'), user.pw_gid, byref(GIDlist), byref(nGIDlist))


            for i in range(0, ct):
                gid = GIDlist[i]
                groupsList.append(grp.getgrgid(gid).gr_name)

        except KeyError as e:
            logging.exception(e)

        return groupsList

if __name__ == "__main__":
    myGroups = groups()
    username = "zack.ramjan"
    print(myGroups.getGroups(username.split("@")[0]))
    username = "zack.ramjan@vai.org"
    print(myGroups.getGroups(username.split("@")[0]))
    username = "ASDASDAS"
    print(myGroups.getGroups(username.split("@")[0]))
