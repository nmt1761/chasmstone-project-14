# chasmstone-project-14
William Boylin - Nathan Trumble - Devon Dighe - Abdullah Sakyl

This is project-14's standalone implementation of the CHASM protocol developed by Geoff Twardocus and Hanif Rahbari at RIT. This code utilizes certificate fragmentation to enable post quantum secure authentication over CV2X networks.

Below is an outline of each file:

CHASM-structs
containing custom structures like fragment, SPDU etc

crypto-handler
our own way of making interactions with the falcon library much easier

recieve (type here, there are two different spellings)
based off of algorithm 2 in the chasm paper

transmit
based off of algorithm 1 in the chasm paper, containing our fragmentation function
- currently unfinished, this is where we believe you should start if you are looking to continue work on this project
