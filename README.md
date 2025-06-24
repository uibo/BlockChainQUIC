# BlockChainQUIC
> Ethereum Execution Layer를 간단하게 모의구성하고 통신 프로토콜을 QUIC으로 대체하여 기존 TCP+RLPx와 성능을 비교해보고자 한다.  
- Client 브랜치는 TCP/RLPx-single 프로젝트  
- ClientQuic 브랜치는 QUIC/RLPx 4stream 프로젝트 
- 브랜치 이름중에 -single이 붙은 것은 단일 스트림으로 구성된 통신 코드, 붙지 않은것은 멀티 스트림으로 구성된 통신 코드
## 주요 파일 소개
```
각 프로젝트는 poetry로 관리된다. 내부 소문자로 구성된 폴더안에 구현체가 존재한다.

client_.py                 실제 통신을 하는 동작이 구현되어있다. config.py에서 현재 장치의 IP와 포트번호를 가져와 소켓을 열고 상대측에게 메시지를 보내고, 수신해서 처리한다.
RLPx_layer.py              Ethereun의 RLPx 계층의 동작을 수행한다. 통신하는 두 프로세스는 연결직후 class RLPx_Layer()의 instance를 만들고, 해당 instance를 통해 메시지를 보내기전의 암호화, framing을 거친다. 수신 측에선 받은 메시지를 이 객체를 통해 디프레이밍, 복호화를 거친다.
├── config/config.py       소켓을 여는 소스코드에서 사용할 IP와 포트번호를 정의한다.
└── config/tx_pool.py      주고 받을 메시지인 Transaction을 정의한다.
```
