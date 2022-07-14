# -*- coding:utf-8 -*-

import re


class tagParser:
    def replace(tagname, srctext, level, replacetext):
        """
        输入内容：标签名称，源文本，安全等级，和用于替换的文字。
        标签名称只能有一个，因此多个标签的内容替换就需要多次遍历。
        源文本顾名思义。
        安全等级（本系统中定义为0-5,但实现上可以随意设定）即能查看标签内内容的所需等级。
        如果等级小于它内容会被 replacetext 替换。
        """
        taglength = len(tagname)
        pos1 = 0
        while True:
            matchObj = re.search(r"<%s [0-9]>" % tagname, srctext, re.M | re.I)
            if matchObj == None: # 啥也没发现就返回并终止循环了
                result = srctext
                break
            pos1 = matchObj.span()[0]
            levelpos = pos1 + taglength + 2
            taglevel = int(srctext[levelpos])
            pos2 = srctext.find("</%s>" % tagname, pos1)
            if pos2 == -1: # 有标签的开始部分，但却没有结束部分，报错（这么做可能会导致直接崩服？）
                raise SyntaxError("Missing '</%s>'" % tagname)
            else:
                pos2 = pos2 + taglength + 3
            if level >= taglevel:
                srctext = srctext.replace(
                    srctext[pos1:pos2], srctext[pos1 + taglength + 4 : pos2 - taglength - 3]
                )
            else:
                srctext = srctext.replace(srctext[pos1:pos2], replacetext)
        ### 替换所有转义符
        """ while True:
            if matchObj == None: # 啥也没发现就返回并终止循环了
                break
            matchObj = re.search(r"\\/", srctext, re.M | re.I) """
        return result


if __name__ == "__main__":
    print(tagParser.replace("blocked","<blocked 3>64-7-1502</blocked>", 2, "Fuck"))
    print(tagParser.replace("example1","<example1 5>187277</example1>!aknsinsins<example1 2>xxx</example1>", 3, "..."))
