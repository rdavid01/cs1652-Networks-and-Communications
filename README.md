# cs1652-Networks-and-Communications
Projects for Professor Babay's 1652 course

1.**Project 1: HTTP 1.0 protocol (working subset of complete protocol)**
  - Built a web client and server using socket programming
    - The HTTP client can retreive files from a web page or a computer 
    - Two different serveres were built, one can handle a single connection, the other handles multiple connections
  
2.**Project 2: TCP module for petnet TCP/IP stack**
  - Implements a subset of full TCP functionality
  - Uses stop and wait protocol along with retransmisstions to enable communication with any other functional TCP implemetation
  - Includes basic timeout handling to aid in detecting lost packets

3.**Project 3: Link state and distance vector routing protocols**
  - Implements routing and forwarding logic for overlay nodes
    - Works with arbitrary setup of nodes and edges
    - overlay nodes send heartbeat and echo packets over UDP
      - Detects failure and recovery of edges
      - Updates best route accordingly
