# ChatangoAccountRestorer
A multithreaded tool which uses proxy workers to help you restore accounts on chatango that you have lost access to

Note: If you read the code you will see that it does not gracefully close worker threads, which can be changed by uncommenting code responsible for this.  The reason to not gracefully close worker threads is because public proxies tend to suck and therefore cause the code to hang for quite a long time, depending on how many public proxies you are using.
