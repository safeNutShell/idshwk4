@load  base/protocols/krb/main.zeek 
#统计时间
global TimeSlice : time = network_time();
#开启计时，只在第一个response报文时使用
global NewSlice : bool = T;
#每一个外部ip对应的必要统计信息
type Statistic : record{
	ErrRes : count;	#404数量
	AllRes : count;	#总数
	URLInfo : table[string] of count;	#该IP访问的URL信息
};
#针对每个ip进行统计
global Suspect : table[addr] of Statistic = table();

event zeek_init() 
{
	#do nothing
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	#对数据进行统计
	if(c$id$orig_h !in Suspect){
		local Empty : table[string] of count = table();
		Suspect[c$id$orig_h] = Statistic($ErrRes=0, $AllRes=0, $URLInfo=Empty);
	}
	++Suspect[c$id$orig_h]$AllRes;
	if(code==404){
		++Suspect[c$id$orig_h]$ErrRes;
		if(c$http$uri in Suspect[c$id$orig_h]$URLInfo)
			++Suspect[c$id$orig_h]$URLInfo[c$http$uri];
		else
			Suspect[c$id$orig_h]$URLInfo[c$http$uri] = 1;
	}	
	#辅助启动首次TimeSlice
	if(NewSlice){
		TimeSlice = network_time();
		NewSlice = F;
	}
	local intervaltime : interval = network_time() - TimeSlice;
	#已经过十分钟，开始判断
	if(intervaltime > 10min){
		for(i in Suspect){
			if(Suspect[i]$ErrRes > 2){
				if((Suspect[i]$ErrRes)*10/(Suspect[i]$AllRes) >= 2){
					local Unique : count = 0;
					local Attempts : count = 0;
					for(j in Suspect[i]$URLInfo){
						++Unique;
						Attempts += Suspect[i]$URLInfo[j];
					}
					if(Unique*10/(Suspect[i]$ErrRes) >= 5){
						print fmt("%s is a scanner with %d scan attempts on %d urls", i, Attempts, Unique);
					}
				}
			}
		}
		#清空数据结构，在下一个时间片重新统计
		#print Suspect;
		Suspect = table();
		#开启一个新的slice
		TimeSlice = network_time();
	}
}

event zeek_done()
{
	#print Suspect;
	#以妨最后一个分片没有到10分钟；在退出时对Suspect清算
	for(i in Suspect){
		if(Suspect[i]$ErrRes > 2){
			if((Suspect[i]$ErrRes)*10/(Suspect[i]$AllRes) >= 2){
				local Unique : count = 0;
				local Attempts : count = 0;
				for(j in Suspect[i]$URLInfo){
					++Unique;
					Attempts += Suspect[i]$URLInfo[j];
				}
				if(Unique*10/(Suspect[i]$ErrRes) >= 5){
					print fmt("%s is a scanner with %d scan attempts on %d urls", i, Attempts, Unique);
				}
			}
		}
	}
	
	print "Work done!";
}
