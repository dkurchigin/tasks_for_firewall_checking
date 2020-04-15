from configparser import RawConfigParser

from sqlalchemy import create_engine, Column, Integer, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

import os

local_config_path = os.path.join(os.getcwd(), 'local.conf')
config = RawConfigParser()
config.read(local_config_path)

user = config.get('main', 'USER')
passwd = config.get('main', 'PASSWORD')
server_db = config.get('main', 'DB_HOST')

CONNECTION_STRING = f'postgresql+psycopg2://{user}:{passwd}@{server_db}/analiz_trafic'
engine = create_engine(CONNECTION_STRING, echo=False)
Session = sessionmaker(bind=engine)
session = Session()

Base = declarative_base()


class InputPackets(Base):
    __tablename__ = 'input_packets'

    id = Column(Integer, primary_key=True, autoincrement=True)
    frame_number = Column(Integer)
    frame_time = Column(DateTime)
    source_ip = Column(Text)
    source_nat_ip = Column(Text)
    destination_ip = Column(Text)
    destination_nat_ip = Column(Text)
    source_port = Column(Integer)
    source_nat_port = Column(Integer)
    destination_port = Column(Integer)
    destination_nat_port = Column(Integer)
    start_stream = Column(DateTime)
    end_stream = Column(DateTime)

    def __repr__(self):
        return f"<INPUT Packet({self.id}, {self.frame_number}, {self.frame_time})>"


class OutputPackets(Base):
    __tablename__ = 'output_packets'

    id = Column(Integer, primary_key=True, autoincrement=True)
    frame_number = Column(Integer)
    frame_time = Column(DateTime)
    source_ip = Column(Text)
    source_port = Column(Integer)
    nat_ip = Column(Text)
    port_nat_begin = Column(Integer)
    port_nat_end = Column(Integer)
    destination_ip = Column(Text)
    destination_port = Column(Integer)
    session_begin = Column(DateTime)
    session_end = Column(DateTime)
    packet_number = Column(Integer)
    traffic_type = Column(Integer)

    def __repr__(self):
        return f"<OUTPUT Packet({self.id}, {self.frame_number}, {self.frame_time})>"


def load_input_packet(row_):
    new_record = InputPackets()
    new_record.frame_number = row_['frame_number']
    new_record.frame_time = row_['frame_time']
    new_record.source_ip = row_['source_ip']
    new_record.source_nat_ip = row_['source_nat_ip']
    new_record.destination_ip = row_['destination_ip']
    new_record.destination_nat_ip = row_['destination_nat_ip']
    new_record.source_port = row_['source_port']
    new_record.source_nat_port = row_['source_nat_port']
    new_record.destination_port = row_['destination_port']
    new_record.destination_nat_port = row_['destination_nat_port']
    new_record.start_stream = row_['start_stream']
    new_record.end_stream = row_['end_stream']
    session.add(new_record)


def load_output_packet(row_):
    new_record = OutputPackets()
    new_record.frame_number = row_['frame_number']
    new_record.frame_time = row_['frame_time']
    new_record.source_ip = row_['source_ip']
    new_record.source_port = row_['source_port']
    new_record.nat_ip = row_['nat_ip']
    new_record.port_nat_begin = row_['port_nat_begin']
    new_record.port_nat_end = row_['port_nat_end']
    new_record.destination_ip = row_['destination_ip']
    new_record.destination_port = row_['destination_port']
    new_record.session_begin = row_['session_begin']
    new_record.session_end = row_['session_end']
    new_record.packet_number = row_['packet_number']
    new_record.traffic_type = row_['traffic_type']
    session.add(new_record)


def commit_():
    session.commit()
