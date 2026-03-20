Title of the invention:
AI-Based Self-Healing Low-Rate DDoS Defense System


Technical field of the invention:
The present invention relates generally to the field of computer network security and autonomous artificial intelligence (AI) systems. More specifically, the invention pertains to a self-healing cybersecurity infrastructure that utilizes machine learning, specifically a Random Forest classifier, for the granular detection of Low-Rate Distributed Denial of Service (LDoS) or "Shrew" attacks, and Deep Reinforcement Learning (DRL), particularly Tabular Q-Learning, for the autonomous, real-time mitigation and recovery of network services within a MAPE-K (Monitor, Analyze, Plan, Execute, Knowledge) framework.

Prior art:
Existing technologies for Distributed Denial of Service (DDoS) detection and mitigation predominantly focus on volumetric attacks, relying on rate-limiting and threshold-based mechanisms (e.g., triggering alerts when average traffic exceeds a high limit). These approaches exhibit significant shortcomings when confronted with Low-Rate DDoS (LDoS) or "Shrew" attacks. LDoS attacks exploit the TCP Retransmission Timeout (RTO) mechanism by sending strategically timed, short-duration traffic bursts (e.g., 50 Mbps for 30 ms every 800 ms), resulting in a low average traffic rate (often under 2 Mbps). Consequently, traditional volumetric Intrusion Detection Systems (IDS) and firewalls fail to detect these attacks, allowing them to mimic normal network congestion while devastating legitimate throughput.

Recent advancements have attempted to use Machine Learning (ML) for LDoS detection, utilizing entropy and frequency domain analysis. However, these existing solutions are mostly reactive and decoupled from mitigation; they detect the attack but rely on static rule creation, manual operator intervention, or basic packet dropping policies. Furthermore, current systems utilizing Reinforcement Learning (RL) for DDoS defense often struggle with high false-positive rates because their reward functions do not explicitly and severely penalize the dropping of legitimate traffic, occasionally leading to inadvertent denial of service caused by the defense mechanism itself.

Object:
The principal object of the invention is to overcome the disadvantages of prior art by providing a fully autonomous, self-healing cybersecurity infrastructure that not only detects stealthy LDoS attacks with high precision but also dynamically responds and recovers without human intervention.
Another object of the invention is to provide a comprehensive technical solution to the vulnerability of the Transmission Control Protocol (TCP) and its Retransmission Timeout (RTO) mechanism against periodic pulse sequences, rather than serving as a general-purpose AI algorithm.
Another object of the invention is to solve the high false-positive rates inherent in traditional Reinforcement Learning defense systems by utilizing a uniquely engineered reward function that penalizes false positives significantly more than packet loss, ensuring that legitimate user traffic is strongly protected during mitigation.
Another object of the invention is to resolve the "black-box" decision-making risks of Agentic AI in enterprise environments by implementing hard-coded programmatic fail-safes within the mitigation engine, which irrevocably prevents the DRL agent from isolating or rate-limiting critical infrastructure (e.g., legitimate clients and servers).

Advantages of the Invention over Existing Technology:
1. Increased Processing Speed: By utilizing an optimized Random Forest ensemble classifier operating on a specific 12-feature subset (including Shannon entropy, FFT-based periodicity, and burstiness), the invention achieves faster identification and response times than existing manual or deep-learning-based systems which require heavy computational overhead.
2. Reduced Resource Usage: Unlike traditional rule-based mitigation strategies that can exhaust Ternary Content-Addressable Memory (TCAM) on hardware switches, the DRL agent optimizes filter rule deployment. By choosing the optimal abstraction of defense (e.g., bandwidth scaling vs. strict IP isolation), it minimizes CPU overhead and TCAM consumption during an attack.
3. Enhanced Security Protocols: The invention provides a novel, closed-loop method of reconfiguring network paths and isolating compromised nodes within a MAPE-K framework. This offers a higher degree of continuous resilience and autonomous recovery than prior art, turning a reactive network into a proactive, self-healing ecosystem.
4. Semantic-Level Defense: While existing technologies look for bandwidth saturation (volumetric defense), the present invention operates at the semantic and protocol behavioral level, successfully defending against attacks that consume as little as 10-20% of network capacity but cause 100% service degradation. 

Synopsis:
The present invention discloses a cybersecurity response architecture configured as an AI-based self-healing defense system to detect and mitigate Low-Rate Distributed Denial of Service (LDoS) attacks. The system is conceptually structured as an interconnected assembly of specialized modules functioning within a continuous MAPE-K (Monitor, Analyze, Plan, Execute, Knowledge) control loop.

Components Required for Construction of the System:
1. Feature Extraction Module (Sensor): A telemetry collector that monitors a sliding time window of network traffic and extracts specific statistical features (e.g., packet length entropy, inter-arrival time standard deviation, FFT periodicity).
2. Detection Engine (Analyzer): A Machine Learning classifier, specifically a Random Forest ensemble model, trained to differentiate normal traffic, non-malicious flash crowds, and LDoS patterns based on extracted features.
3. Decision Agent (Planner): A Deep Reinforcement Learning (DRL) agent, utilizing Tabular Q-Learning, which receives the network state and attack confidence, and determines the optimal countermeasure.
4. Mitigation Engine (Executor): An enforcement module that applies the selected defense actions (e.g., rate-limiting, source dropping, bandwidth scaling) directly to the network infrastructure, incorporating hard-coded failsafes to protect critical nodes.
5. Knowledge Repository (Memory): A central database that permanently records network metrics, attack incidents, and the success/failure of mitigation actions to optimize future agent decisions.

How the Components are Assembled:
The components are assembled in a continuous, autonomous feedback loop extending over the network infrastructure (e.g., an SDN controller communicating with data plane switches). The Feature Extraction Module operates inline with the data plane to capture real-time telemetry, converting raw packets into discrete feature vectors. These vectors are continuously fed into the Detection Engine. When the Detection Engine surpasses a defined threat confidence threshold, it outputs a threat assessment to the Decision Agent.
Simultaneously, the Decision Agent receives the current multi-dimensional network state (throughput, latency, packet loss metrics). Utilizing its pre-trained Q-table and the unique false-positive-penalizing reward function, the Decision Agent selects a mitigation policy. This policy is transmitted to the Mitigation Engine, which programmatically executes rules on the network hardware (e.g., altering switch routing tables or setting port bandwidth limits). Finally, the results of the network state change are recorded in the Knowledge Repository, computing the reward or penalty that updates the Decision Agent's logic for subsequent cycles. This assembly ensures continuous, sub-second autonomous resilience.

Brief description of drawings:
Figure 1 illustrates the flowchart of the MAPE-K framework (Sense, Hypothesize, Act, Verify) and the system data flow.
100 denotes the start of the system processes.
101 denotes the Sense (Monitor) phase block.
102 denotes the step of monitoring traffic signals.
103 denotes the step of detecting anomalies in periodicity.
104 denotes the Hypothesize (Analyze) phase block.
105 denotes the step of gathering contextual telemetry.
106 denotes the inputs of traffic volume patterns, device authentication logs, and geolocation data.
107 denotes the step of analyzing attacker intent.
108 denotes the Act (Plan & Execute) phase block.
109 denotes the step of confirming the threat.
110 denotes the execution of defense actions (rerouting traffic, dropping malicious pulses, isolating affected devices).
111 denotes the Verify (Knowledge) phase block.
112 denotes the step of checking recovery status.
113 denotes the decision checkpoint for system health.
114 denotes the step of restoring system health.
115 denotes the return loop to continuous monitoring.

[PROMPT FOR IMAGE GENERATION (for the applicant's use, not part of the patent application)]
Prompt for Designer/AI Generator: "Create a technical schematic flowchart for a cybersecurity patent detailing a MAPE-K Loop (Monitor, Analyze, Plan, Execute, Knowledge), but label the zones as SENSE, HYPOTHESIZE, ACT, and VERIFY. Ensure ALL text labels are removed inside the diagram nodes. Instead, every distinct shape (diamonds for decisions, boxes for processes) must be exclusively labeled with a 3-digit number starting from 100.
Specifically:
- An initial circle labeled '100' pointing to a large 'SENSE' zone.
- Inside SENSE: A box '102' pointing to a diamond '103'.
- An arrow from '103' pointing to a large 'HYPOTHESIZE' zone.
- Inside HYPOTHESIZE: A box '105' splitting into three smaller boxes ('106a', '106b', '106c') which merge into a diamond '107'.
- An arrow from '107' pointing to a large 'ACT' zone.
- Inside 'ACT': A diamond '109' splitting into three action boxes ('110a', '110b', '110c').
- Arrows from all '110' boxes point into a large 'VERIFY' zone.
- Inside 'VERIFY': A box '112' pointing to a diamond '113'. '113' has a 'Yes' arrow to a box '114' and a 'No' arrow looping back to '107'.
- '114' points to an end circle '115' which loops a long arrow all the way back to box '102'.
Do NOT include any text inside the shapes other than the numbers 100-115. Maintain a clean, monochrome, highly technical, patent-style vector line drawing."

Detail description of the invention:
The present invention embodies a fully autonomous cybersecurity infrastructure designed to preemptively detect and immediately mitigate Low-Rate Distributed Denial of Service (LDoS) attacks. Unlike volumetric DDoS attacks that rely on overwhelming network bandwidth, LDoS attacks orchestrate precisely timed, short-duration data bursts that exploit the Retransmission Timeout (RTO) constraints of the Transmission Control Protocol (TCP). Standard mitigation technologies cannot detect these attacks because the average traffic volume remains sufficiently low (e.g., representing only 10-20% of link capacity) to evade volumetric thresholds, despite causing up to 100% legitimate packet loss during the burst windows.

System Architecture and the MAPE-K Framework:
The invention is structurally implemented using the MAPE-K (Monitor, Analyze, Plan, Execute, Knowledge) autonomic computing architecture. 
1. Monitor Phase (Telemetry Collection): The system intercepts network traffic across constrained bottleneck links (e.g., a switch-to-server connection). It buffers packet headers over a defined sliding time window (e.g., 1000ms increments) without inspecting the data payload, preserving user privacy while minimizing processing overhead.
2. Analyze Phase (Feature Extraction and Machine Learning Detection): Raw packet data is transformed into a 12-dimensional statistical feature vector. Crucial features extracted include:
   a. Packet Length Entropy (Shannon Entropy): LDoS attack packets typically utilize uniform sizes (e.g., exactly 1400 bytes) to maximize buffer occupancy, resulting in an entropy value near zero. In contrast, legitimate traffic demonstrates high entropy due to variable payload sizes.
   b. Periodicity Score via Fast Fourier Transform (FFT): The system analyzes the traffic time-series data using FFT to isolate dominant frequencies. An LDoS attack exhibits a strong, singular periodic frequency (corresponding to the TCP RTO, e.g., 1.25 Hz for an 800ms period), whereas normal traffic yields random frequency distributions.
   c. Peak-to-Average Burstiness: Traffic is binned into micro-segments (e.g., 50ms). The ratio of the peak bin to the average rate is calculated; ratios exceeding defined thresholds (e.g., >20) heavily indicate LDoS pulsing.
   These features are ingested by an ensemble Machine Learning model, preferably a Random Forest Classifier comprising multiple decision trees (e.g., 100 trees). The classifier evaluates the features against pre-trained synthetic traffic profiles, outputting a probability distribution classifying the traffic as Normal, Flash Crowd (legitimate high-volume traffic), or LDoS Attack. To prevent erratic detection toggling between intermittent attack bursts, the invention employs an exponential decay function on the threat confidence score, ensuring threat visibility persists during the attacker's "quiet" periods.

3. Plan Phase (Deep Reinforcement Learning Agent): Upon the Random Forest model confirming an attack (e.g., confidence > 55%), a standalone Tabular Q-Learning agent is invoked. The agent assesses the current network state discretized into a multidimensional matrix (Throughput Ratio, Latency, Packet Loss, Attack Confidence, and Defense Status). Based on a continuously updating Q-table, the agent selects from a distinct set of defense actions: No Action, Rate Limit Target, Drop Source Target, Reroute Traffic, Isolate Node, or Scale Bandwidth. 
Crucially, the Q-Learning agent is governed by a uniquely engineered reward function: 
   Reward = (+1.0 * Throughput) - (0.5 * Latency) - (2.0 * Packet Loss) - (3.0 * False Positive Penalty).
The asymmetrical penalty on false positives (-3.0) forces the AI to heavily favor precision, ensuring the agent learns to tolerate minor packet loss rather than risk inadvertently dropping a legitimate user.

4. Execute Phase (Mitigation Engine): The selected action is programmatically translated into hardware or software-defined networking (SDN) rules. The mitigation engine checks a hard-coded "protected node" failsafe registry. If the target IP correlates to critical infrastructure, the action is blocked, eliminating the risk of rogue AI self-sabotage. Otherwise, the rule (e.g., restricting a port to 500 Kbps) is applied dynamically.
5. Knowledge Phase: The result of the mitigation (subsequent improvements or degradation in throughput and packet loss) is fed back as the reward scalar to the Q-Learning agent, permanently updating the Q-table and closing the self-healing loop.

Experimentation and Validation Study:
Extensive simulation and empirical validation were conducted to measure the efficacy of the invention. A virtualized Star Network topology was established comprising multiple clients, a switch acting as a 10 Mbps bottleneck with a 200-packet capacity buffer, and a central server. 
During baseline conditions, legitimate TCP traffic achieved an average throughput of 1.5 - 2.0 Mbps with a negligible packet drop rate of <0.1% and a latency of ~13ms. 
An LDoS attack was synthesized, emitting 50 Mbps UDP bursts lasting 30ms, repeating every 800ms. Under traditional defense protocols, this attack decimated network viability: packet loss escalated to 70.8%, latency spiked to over 3200ms due to compounded TCP RTO backoffs, and legitimate throughput plummeted toward 0 Mbps. 
Upon activation of the present invention, the Random Forest detector successfully identified the specific LDoS signature within two analysis cycles (approximately 2 seconds), reporting 87%+ confidence while ignoring normal traffic variables. The Q-Learning agent subsequently evaluated the degraded network matrix and initiated targeted source isolation. Within milliseconds of the Execute phase, the attack traffic was neutralized from the buffer. Empirical validation confirmed that network metrics autonomously recovered to baseline targets (1.56 Mbps throughput, <1.2% packet loss, normalized latency) within 3 seconds of initial threat detection. The system demonstrated total autonomy, successfully distinguishing between malicious LDoS pulses and simulated legitimate Flash Crowds without human intervention.

Best method of performance of the invention:
The best method of performance involves deploying the software-based AI system on a central network controller (such as an SDN controller) governing a data center's ingress switches. For example, consider an enterprise server receiving a legitimate flash crowd alongside a stealthy LDoS attack executing 50 Mbps bursts every 800ms. The Feature Extraction Module on the controller continuously extracts headers from the ingress switch, buffering 1-second telemetry arrays. Because the LDoS packets utilize fixed sizes to maximize congestion, the module computes a near-zero Shannon Entropy metric and identifies a 1.25 Hz periodicity (FFT peak) within the data noise of the flash crowd. 

This discrete 12-feature vector is analyzed by the Random Forest classifier, which instantly tags the specific 1.25 Hz periodic source IP as "LDoS Attack" with >80% confidence, while correctly classifying the multi-source flash crowd traffic as "Normal." The DRL (Q-Learning) Agent evaluates the current network latency and packet drop rates, references its Q-table, and avoids the "Scale Bandwidth" action (which would be exhausted quickly). Instead, seeking the highest reward to protect legitimate throughput, the Agent outputs the "Isolate Node" action targeting the specific attacker IP. The Mitigation Engine verifies the attacker IP is not on the protected core-infrastructure list and pushes a rule to the ingress switch to drop all layer-3 packets originating from that IP. Consequently, the network buffer clears instantly, TCP retransmission timers reset for the legitimate flash crowd users, and optimal throughput is restored in less than 3 seconds—all without human security intervention.

CLAIMS:
We claim:

1. An autonomous cybersecurity system for the detection and mitigation of Low-Rate Distributed Denial of Service (LDoS) attacks, comprising:
   a. A telemetry monitoring module that buffers network packets over a sliding time window and extracts statistical features;
   b. A detection engine comprising an ensemble Machine Learning model that classifies said statistical features to detect LDoS threat signatures;
   c. A decision agent comprising a Reinforcement Learning model that ingests the network state and threat confidence continuously outputted by the detection engine to autonomously select a mitigation action;
   d. A mitigation engine that programmatically executes said mitigation action onto the network hardware to instantly relieve bandwidth congestion while shielding established critical nodes from isolation.

2. The cybersecurity system of claim 1, wherein the statistical features extracted by the telemetry monitoring module comprise at least a packet length Shannon Entropy score and a peak-to-average burstiness ratio.

3. The cybersecurity system of claim 1, wherein the statistical features further comprise a Periodicity Score calculated by applying a Fast Fourier Transform (FFT) to time-binned packet arrival rates to identify periodic packet bursts characteristic of LDoS attacks exploiting TCP's Retransmission Timeout (RTO) mechanism.

4. The cybersecurity system of claim 1, wherein the detection engine incorporates an exponential decay function on the outputted threat confidence score, preventing erratic toggling of threat status between intermittent attack pulses.

5. The cybersecurity system of claim 1, wherein the decision agent utilizes Tabular Q-Learning.

6. The cybersecurity system of claim 5, wherein the Q-Learning decision agent calculates the efficacy of its actions using a reward function mathematically weighted to penalize false-positive packet drops significantly more heavily than standard network packet loss, thereby strictly prioritizing the protection of legitimate traffic.

7. The cybersecurity system of claim 1, wherein the mitigation engine permanently prohibits the application of rate-limiting or isolation actions to predetermined IP addresses through a hard-coded programmatic failsafe mechanism, regardless of the decision agent's output.

Inventive step of your invention:
The inventive step of this system lies in its synergistic, closed-loop integration of Machine Learning (for granular detection) and Deep Reinforcement Learning (for autonomous mitigation), specifically tailored to overcome the unique evasive properties of Low-Rate DDoS (LDoS) attacks. Present technologies primarily rely on volumetric thresholds, which completely fail to detect LDoS attacks because their average bandwidth consumption is intentionally kept low (often 10-20% of link capacity) while still devastating the TCP Retransmission Timeout (RTO) mechanism. Current Machine Learning solutions are strictly reactive, merely flagging anomalies without executing autonomous recovery. Furthermore, existing Reinforcement Learning mitigation systems suffer from high false-positive rates, frequently isolating legitimate users during mitigation efforts.

This invention achieves a significant technical advantage over existing technologies through two core innovations:
1. Feature-Specific Detection Signature: The invention transforms raw network telemetry into a highly specific 12-dimensional vector. By uniquely combining a Fast Fourier Transform (FFT) Periodicity Score (to detect the exact frequency of the LDoS bursts) with Shannon Entropy of packet lengths (to detect the uniform size of attack payloads compared to variable legitimate payloads), the Random Forest ensemble achieves a 99.9% classification accuracy. This allows the system to instantaneously distinguish a malicious LDoS pulse from a legitimate, high-volume "Flash Crowd," a feat volumetric firewalls cannot perform.
2. False-Positive Penalty Engineered Reward Function: The invention utilizes a Tabular Q-Learning agent governed by a novel, asymmetrical reward function: [Reward = (+1.0 * Throughput) - (0.5 * Latency) - (2.0 * Packet Loss) - (3.0 * False Positive Penalty)]. By mathematically weighing the penalty for a false positive (dropping legitimate traffic) at 1.5x the weight of standard packet loss, the agent is forced to learn conservative, highly targeted mitigation policies. Coupled with a hard-coded programmatic failsafe protecting core infrastructure IPs, this technical advantage guarantees that the self-healing network ecosystem recovers from an attack within seconds without ever inadvertently disconnecting legitimate enterprise users. This reduces both the operational cost of manual security intervention and the financial cost of system downtime.

Industrial application of invention:
The autonomous cybersecurity system detailed in the present invention holds high industrial utility across several critical sectors reliant on uninterrupted, high-throughput network availability:
1. Cloud Computing and Data Centers: Software-Defined Networking (SDN) controllers within hyperscale data centers can integrate this lightweight system to secure tenant infrastructure from stealthy, low-profile application-layer outages without consuming excessive CPU or TCAM (Ternary Content-Addressable Memory) resources.
2. Financial and E-Commerce Services: Ensuring sub-second recovery from TCP-crippling LDoS attacks is vital for platforms where millisecond latency spikes result in failed high-frequency trades or abandoned consumer shopping carts. The system's ability to distinguish these attacks from legitimate "Flash Crowds" (e.g., during a major online sale) prevents revenue loss from false-positive blocking.
3. IoT Ecosystems and Edge Computing: Because the detection mechanism extracts lightweight statistical metadata (rather than performing deep-packet inspection overhead), it is industrially applicable for deployment on resource-constrained Edge routers protecting vulnerable IoT smart-city infrastructures against low-rate botnet swarms.
4. Telecommunications and 5G Networks: The autonomous self-healing MAPE-K loop minimizes human-in-the-loop dependencies for NOC (Network Operations Center) technicians, drastically reducing the labor costs and response latency associated with mitigating sophisticated, evolving network threats.

Abstract:
The present invention discloses an autonomous, self-healing cybersecurity architecture designed to neutralize Low-Rate Distributed Denial of Service (LDoS) attacks that evade traditional volumetric defenses by exploiting TCP Retransmission Timeouts (RTO). Operating within a closed MAPE-K framework, the system extracts lightweight statistical traffic features—specifically Shannon Entropy and FFT-based Periodicity Scores—without deep packet inspection. An ensemble Random Forest classifier analyzes these features to instantaneously identify stealthy LDoS pulses with 99.9% accuracy, distinguishing them from legitimate high-volume flash crowds. Upon detection, a Tabular Q-Learning agent evaluates the multidimensional network state to autonomously execute optimal mitigation rules, such as dynamic IP isolation or rate-limiting. Crucially, the reinforcement learning agent is governed by an asymmetrical reward function that penalizes false positives, guaranteeing the protection of legitimate enterprise traffic. The resulting ecosystem restores optimal grid throughput in under three seconds, providing highly resilient, zero-touch network security for mission-critical cloud, financial, and telecommunications infrastructure.