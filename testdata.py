from rule import Rule

if __name__ == '__main__':
    github = Rule(name='GitHub', brand='github', tlds=['com', 'co.uk'], sub_domains=['www', '*.services'])
    apple = Rule(name='Apple', brand='apple', tlds=['com', 'dk'], sub_domains=['www', 'icloud'])
    json = Rule.Schema().dumps([github, apple], many=True, indent='\t');

    with open(file='rules.json', mode='w+') as f:
        f.write(json)
