from setuptools import setup, find_packages

setup(
    name="streamlit-cognito-auth",
    version="1.1.1",
    packages=find_packages("src"),
    package_dir={"": "src"},
    include_package_data=True,
    install_requires=[
        "boto3 >= 1.26.52",
        "pycognito >= 2022.12.0",
        "streamlit >= 1.17.0",
        "extra_streamlit_components >= 0.1.56",
    ],
    author="Sarawin Khemmachotikun",
    author_email="khemmachotikun.s@gmail.com",
    description="A Streamlit component for authenticating users with AWS Cognito",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/pop-srw/streamlit-cognito-auth",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
