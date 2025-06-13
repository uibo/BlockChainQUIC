# BlockChainQUIC

Ethereum Execution layer를 간단하게 모의구성하고 통신 프로토콜을 QUIC으로 대체하여 기존 TCP+RLPx와 성능을 비교해보고자 한다.

Client는 TCP/RLPx-single 프로젝트  
ClientQuic은 QUIC/RLPx 4stream 프로젝트이다.  

branch name중에 -single이 붙은 것은 단일 스트림, 붙지 않은것은 멀티 스트림 구현 브랜치이다.
