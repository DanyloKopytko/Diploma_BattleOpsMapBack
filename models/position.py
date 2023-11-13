from app import db


class Position(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    position_type = db.Column(db.Integer)
    position_count = db.Column(db.Integer)
    description = db.Column(db.String(500))

    @property
    def serialize(self):
       """Return object data in easily serializable format"""
       return {
           'id': self.id,
           'position_type': self.position_type,
           'description'  : self.description,
           'position_count': self.position_count,
           'name': self.name
       }