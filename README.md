# AI-Powered Malware Detection App

![alt text](https://github.com/rejzzzz/Team_Rwanda/image.jpg?raw=true)

## Overview

This desktop cybersecurity application analyzes running processes and predicts potential **malware threats** using a **local machine learning model**. It continuously monitors system metrics like **CPU usage, memory consumption, network activity, and total running processes** to detect suspicious behavior.

## How It Works

-   **Real-time Process Monitoring:** Tracks active processes and system resource usage.
-   **AI-Powered Risk Assessment:** A **TensorFlow/Keras** model assigns a **risk score (0-100)** based on process behavior.
-   **Malware Detection Logic:** Flags processes exceeding predefined **CPU/memory thresholds** as potential threats.
-   **Threat Activity Level:** Instead of random values, it calculates an **actual threat level** based on ML predictions.

## Tech Stack

-   **Frontend:** PyQt5 (GUI)
-   **System Monitoring:** psutil
-   **Machine Learning:** TensorFlow Lite for local inference
-   **Backend Logic:** Python

## Features

**Lightweight & Local** – No cloud dependency, runs entirely on your system.  
**Real-time Monitoring** – Continuously updates process data and security insights.  
**AI-Powered Detection** – Uses machine learning to assess process risks.  
**User-Friendly Interface** – Simple and interactive PyQt5 GUI.
