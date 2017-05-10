#!/usr/bin/python
# -*- coding:utf-8 -*-
import MySQLdb
import jieba
import re
import time
import sys
reload(sys)
sys.setdefaultencoding('utf8')
from jieba import analyse
tfidf=analyse.extract_tags
jieba.load_userdict("./myself_dict.txt")

class A(analyse.TFIDF):

    def extract_tags(self,sentence,topx=5,withWeight=False):
        words=self.tokenizer.cut(sentence)
        freq={}
        for w in words:
            if len(w.strip())<2 or w.lower() in self.stop_words:
                continue
            freq[w]=freq.get(w,0.0)+1.0
        total=sum(freq.values())
        for k in freq:
            kw=k
            freq[k]*=self.idf_freq.get(kw,self.median_idf)/total

        if withWeight:
            tags=sorted(freq.items(),key=itemgetter(1),reverse=True)
        else:
            tags=sorted(freq,key=freq.__getitem__,reverse=True)

        if topx:
            return tags[:topx]
        else:
            return tags

def title():

    conn=MySQLdb.connect('localhost','tom','admin','weixinmonitor_v2',3306,charset='utf8')
    cur=conn.cursor()
    count=cur.execute('select gid from system_grouplist where userid=10')
    res = cur.fetchall()
    # print res

    for n in res:
        print n
        sql = 'select content from system_content where gid= %d and createtime>=DATE_SUB(NOW(),INTERVAL 30 MINUTE)'%n
        content=cur.execute(sql)
        results=cur.fetchall()
        datalist = []
        print len(results)
        for i in results:
            i = i[0]
            if i.startswith('<?xml version="1.0"?>'):
                continue
            if i.startswith('wxid'):
                continue
            if i.startswith('http'):
                continue

            i = re.sub(r'(http|ftp|https)\:\/\/\w*\.\w*\/\w*\/?',' ',i)
            i = re.sub(r'(http|ftp|https)\:\/\/\w*\.\w*\.\w*\/\w*\/\w*\/\w*\/\w*\/\w*\.\w*',' ',i)
            datalist.append(i)
        if not datalist:
            continue
        text=''.join(datalist)
        a=A()
        result_list = a.extract_tags(text,5,withWeight=False)
        if not result_list:
            continue
        f=file("exercise.txt","a+")
        n = n[0]
        f.write(str(n) +': ')
        for i in result_list:
            print i
            f.write( i + ' , ')
        f.write('\n')
        f.close()


if __name__=="__main__":
    while True:
        try:
            title()
        except ValueError,e:
            print 'ValueError:',e
        except ZeroDivisionError,e:
            print 'ZeroDivisionError:',e 
        finally:
            time.sleep(1800)