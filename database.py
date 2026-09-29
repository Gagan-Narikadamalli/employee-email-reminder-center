import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Workbook(Base):
    __tablename__ = "reminder_workbooks"

    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    total_records = Column(Integer, default=0)
    status = Column(String(50), default="completed")
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    employees = relationship("EmployeeRecord", back_populates="workbook", cascade="all, delete")


class EmployeeRecord(Base):
    __tablename__ = "reminder_employee_records"

    id = Column(Integer, primary_key=True)
    workbook_id = Column(Integer, ForeignKey("reminder_workbooks.id"))
    employee_name = Column(String(255))
    email = Column(String(255))
    phone = Column(String(50))
    principal_name = Column(String(255))
    past_due_notes = Column(String(255))
    aftercare_status = Column(String(100))
    analysis_result = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    workbook = relationship("Workbook", back_populates="employees")


def init_database():
    Base.metadata.create_all(engine)


def get_session():
    return SessionLocal()
